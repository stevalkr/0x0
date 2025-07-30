#!/usr/bin/env python3

"""
    Copyright © 2024 Mia Herkt
    Licensed under the EUPL, Version 1.2 or - as soon as approved
    by the European Commission - subsequent versions of the EUPL
    (the "License");
    You may not use this work except in compliance with the License.
    You may obtain a copy of the license at:

        https://joinup.ec.europa.eu/software/page/eupl

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
    either express or implied.
    See the License for the specific language governing permissions
    and limitations under the License.
"""

from flask import Flask, abort, make_response, redirect, render_template, \
    Request, request, Response, send_from_directory, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.datastructures import FileStorage
from sqlalchemy import and_, or_
from sqlalchemy.orm import declared_attr
import sqlalchemy.types as types
from jinja2.exceptions import *
from jinja2 import ChoiceLoader, FileSystemLoader
from hashlib import file_digest
from magic import Magic
from mimetypes import guess_extension
import click
import enum
import os
import sys
import time
import datetime
import ipaddress
import io
import typing
import requests
import secrets
import shutil
import re
from validators import url as url_valid
from pathlib import Path

app = Flask(__name__, instance_relative_config=True)
app.config.update(
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    PREFERRED_URL_SCHEME="https",  # nginx users: make sure to have
                                   # 'uwsgi_param UWSGI_SCHEME $scheme;' in
                                   # your config
    MAX_CONTENT_LENGTH=256 * 1024 * 1024,
    MAX_URL_LENGTH=4096,
    USE_X_SENDFILE=False,
    FHOST_USE_X_ACCEL_REDIRECT=True,  # expect nginx by default
    FHOST_STORAGE_PATH="up",
    FHOST_MAX_EXT_LENGTH=9,
    FHOST_SECRET_BYTES=16,
    FHOST_EXT_OVERRIDE={
        "audio/flac": ".flac",
        "image/gif": ".gif",
        "image/jpeg": ".jpg",
        "image/png": ".png",
        "image/svg+xml": ".svg",
        "video/webm": ".webm",
        "video/x-matroska": ".mkv",
        "application/octet-stream": ".bin",
        "text/plain": ".log",
        "text/plain": ".txt",
        "text/x-diff": ".diff",
    },
    NSFW_DETECT=False,
    NSFW_THRESHOLD=0.92,
    VSCAN_SOCKET=None,
    VSCAN_QUARANTINE_PATH="quarantine",
    VSCAN_IGNORE=[
        "Eicar-Test-Signature",
        "PUA.Win.Packer.XmMusicFile",
    ],
    VSCAN_INTERVAL=datetime.timedelta(days=7),
    URL_ALPHABET="DEQhd2uFteibPwq0SWBInTpA_jcZL5GKz3YCR14Ulk87Jors9vNHgfaOmMX"
                 "y6Vx-",
)

app.config.from_pyfile("config.py")
app.jinja_loader = ChoiceLoader([
    FileSystemLoader(str(Path(app.instance_path) / "templates")),
    app.jinja_loader
])

if app.config["DEBUG"]:
    app.config["FHOST_USE_X_ACCEL_REDIRECT"] = False

if app.config["NSFW_DETECT"]:
    from nsfw_detect import NSFWDetector
    nsfw = NSFWDetector()

try:
    mimedetect = Magic(mime=True, mime_encoding=False)
except TypeError:
    print("""Error: You have installed the wrong version of the 'magic' module.
Please install python-magic.""")
    sys.exit(1)

db = SQLAlchemy(app)
migrate = Migrate(app, db)


class URL(db.Model):
    __tablename__ = "URL"
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.UnicodeText, unique=True)

    def __init__(self, url):
        self.url = url

    def getname(self):
        return su.enbase(self.id)

    def geturl(self):
        return url_for("get", path=self.getname(), _external=True) + "\n"

    @staticmethod
    def get(url):
        u = URL.query.filter_by(url=url).first()

        if not u:
            u = URL(url)
            db.session.add(u)
            db.session.commit()

        return u


class IPAddress(types.TypeDecorator):
    impl = types.LargeBinary
    cache_ok = True

    def process_bind_param(self, value, dialect):
        match value:
            case ipaddress.IPv6Address():
                value = (value.ipv4_mapped or value).packed
            case ipaddress.IPv4Address():
                value = value.packed

        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            value = ipaddress.ip_address(value)
            if type(value) is ipaddress.IPv6Address:
                value = value.ipv4_mapped or value

        return value


class TransferFile():
    def __init__(self, stream, name, content_type):
        self.stream = stream
        self.name = name
        self.sha256 = file_digest(stream, "sha256").hexdigest()

        stream.seek(0, os.SEEK_END)
        self.size = stream.tell()
        stream.seek(0)

        self.mime, self.mime_detected = self.get_mime(content_type)
        self.ext = self.get_ext()

    def get_mime(self, content_type):
        try:
            guess = mimedetect.from_descriptor(self.stream.fileno())
        except io.UnsupportedOperation:
            guess = mimedetect.from_buffer(self.stream.getvalue())

        app.logger.debug(f"MIME - specified: '{content_type}' - "
                         f"detected: '{guess}'")

        if (not content_type
                or "/" not in content_type
                or content_type == "application/octet-stream"):
            mime = guess
        else:
            mime = content_type

        if mime.startswith("text/") and "charset" not in mime:
            mime += "; charset=utf-8"

        return mime, guess

    def get_ext(self):
        ext = "".join(Path(self.name).suffixes[-2:])
        if len(ext) > app.config["FHOST_MAX_EXT_LENGTH"]:
            ext = Path(self.name).suffixes[-1]
        gmime = self.mime.split(";")[0]
        guess = guess_extension(gmime)

        app.logger.debug(f"extension - specified: '{ext}' - detected: "
                         f"'{guess}'")

        if not ext:
            if gmime in app.config["FHOST_EXT_OVERRIDE"]:
                ext = app.config["FHOST_EXT_OVERRIDE"][gmime]
            elif guess:
                ext = guess
            else:
                ext = ""

        return ext[:app.config["FHOST_MAX_EXT_LENGTH"]] or ".bin"

    def save(self, path: os.PathLike):
        with open(path, "wb") as of:
            shutil.copyfileobj(self.stream, of)


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sha256 = db.Column(db.String, unique=True)
    ext = db.Column(db.UnicodeText)
    mime = db.Column(db.UnicodeText)
    addr = db.Column(IPAddress(16))
    ua = db.Column(db.UnicodeText)
    removed = db.Column(db.Boolean, default=False)
    nsfw_score = db.Column(db.Float)
    expiration = db.Column(db.BigInteger)
    mgmt_token = db.Column(db.String)
    secret = db.Column(db.String)
    last_vscan = db.Column(db.DateTime)
    size = db.Column(db.BigInteger)
    filename = db.Column(db.UnicodeText)

    def __init__(self, file_: TransferFile, addr, ua, expiration, mgmt_token):
        self.sha256 = file_.sha256
        self.ext = file_.ext
        self.mime = file_.mime
        self.addr = addr
        self.ua = ua
        self.expiration = expiration
        self.mgmt_token = mgmt_token
        self.filename = file_.name

    @property
    def is_nsfw(self) -> bool:
        if self.nsfw_score:
            return self.nsfw_score > app.config["NSFW_THRESHOLD"]
        return False

    def getname(self):
        return u"{0}{1}".format(su.enbase(self.id), self.ext)

    def geturl(self):
        n = self.getname()
        a = "nsfw" if self.is_nsfw else None

        if self.filename:
            path = f"{n}/{self.filename}"
        else:
            path = n

        return url_for("get", path=path, secret=self.secret,
                       _external=True, _anchor=a) + "\n"

    def getpath(self) -> Path:
        return Path(app.config["FHOST_STORAGE_PATH"]) / self.sha256

    def delete(self, permanent=False):
        self.expiration = None
        self.mgmt_token = None
        self.removed = permanent
        self.getpath().unlink(missing_ok=True)

    """
    Returns the epoch millisecond that a file should expire

    Uses the expiration time provided by the user (requested_expiration)
    upper-bounded by an algorithm that computes the size based on the size of
    the file.

    That is, all files are assigned a computed expiration, which can be
    voluntarily shortened by the user either by providing a timestamp in
    milliseconds since epoch or a duration in hours.
    """
    @staticmethod
    def get_expiration(requested_expiration, size) -> int:
        current_epoch_millis = time.time() * 1000

        # Maximum lifetime of the file in milliseconds
        max_lifespan = get_max_lifespan(size)

        # The latest allowed expiration date for this file, in epoch millis
        max_expiration = max_lifespan + 1000 * time.time()

        if requested_expiration is None:
            return max_expiration
        elif requested_expiration < 1650460320000:
            # Treat the requested expiration time as a duration in hours
            requested_expiration_ms = requested_expiration * 60 * 60 * 1000
            return min(max_expiration,
                       current_epoch_millis + requested_expiration_ms)
        else:
            # Treat expiration time as a timestamp in epoch millis
            return min(max_expiration, requested_expiration)

    """
    requested_expiration can be:
        - None, to use the longest allowed file lifespan
        - a duration (in hours) that the file should live for
        - a timestamp in epoch millis that the file should expire at

    Any value greater that the longest allowed file lifespan will be rounded
    down to that value.
    """
    @staticmethod
    def store(file_: TransferFile, requested_expiration: typing.Optional[int],
              addr, ua, secret: bool):

        if len(file_.mime) > 128:
            abort(400)

        for flt in MIMEFilter.query.all():
            if flt.check(file_.mime_detected):
                abort(403, flt.reason)

        expiration = File.get_expiration(requested_expiration, file_.size)
        isnew = True

        f = File.query.filter_by(sha256=file_.sha256).first()
        if f:
            # If the file already exists
            if f.removed:
                # The file was removed by moderation, so don't accept it back
                abort(451)
            if f.expiration is None:
                # The file has expired, so give it a new expiration date
                f.expiration = expiration

                # Also generate a new management token
                f.mgmt_token = secrets.token_urlsafe()
            else:
                # The file already exists, update the expiration if needed
                f.expiration = max(f.expiration, expiration)
                isnew = False
        else:
            mgmt_token = secrets.token_urlsafe()
            f = File(file_, addr, ua, expiration, mgmt_token)

        f.addr = addr
        f.ua = ua

        if isnew:
            f.secret = None
            if secret:
                f.secret = \
                    secrets.token_urlsafe(app.config["FHOST_SECRET_BYTES"])

        storage = Path(app.config["FHOST_STORAGE_PATH"])
        storage.mkdir(parents=True, exist_ok=True)
        p = storage / file_.sha256

        if not p.is_file():
            file_.save(p)

        f.size = file_.size

        if not f.nsfw_score and app.config["NSFW_DETECT"]:
            f.nsfw_score = nsfw.detect(str(p))

        db.session.add(f)
        db.session.commit()
        return f, isnew


class RequestFilter(db.Model):
    __tablename__ = "request_filter"
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(20), index=True, nullable=False)
    comment = db.Column(db.UnicodeText)

    __mapper_args__ = {
        "polymorphic_on": type,
        "with_polymorphic": "*",
        "polymorphic_identity": "empty"
    }

    def __init__(self, comment: str = None):
        self.comment = comment


class AddrFilter(RequestFilter):
    addr = db.Column(IPAddress(16), unique=True)

    __mapper_args__ = {"polymorphic_identity": "addr"}

    def __init__(self, addr: ipaddress._BaseAddress, comment: str = None):
        self.addr = addr
        super().__init__(comment=comment)

    def check(self, addr: ipaddress._BaseAddress) -> bool:
        if type(addr) is ipaddress.IPv6Address:
            addr = addr.ipv4_mapped or addr
        return addr == self.addr

    def check_request(self, r: Request) -> bool:
        return self.check(ipaddress.ip_address(r.remote_addr))

    @property
    def reason(self) -> str:
        return f"Your IP Address ({self.addr.compressed}) is blocked from " \
                "uploading files."


class IPNetwork(types.TypeDecorator):
    impl = types.Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None:
            value = value.compressed

        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            value = ipaddress.ip_network(value)

        return value


class NetFilter(RequestFilter):
    net = db.Column(IPNetwork)

    __mapper_args__ = {"polymorphic_identity": "net"}

    def __init__(self, net: ipaddress._BaseNetwork, comment: str = None):
        self.net = net
        super().__init__(comment=comment)

    def check(self, addr: ipaddress._BaseAddress) -> bool:
        if type(addr) is ipaddress.IPv6Address:
            addr = addr.ipv4_mapped or addr
        return addr in self.net

    def check_request(self, r: Request) -> bool:
        return self.check(ipaddress.ip_address(r.remote_addr))

    @property
    def reason(self) -> str:
        return f"Your network ({self.net.compressed}) is blocked from " \
                "uploading files."


class HasRegex:
    @declared_attr
    def regex(cls):
        return cls.__table__.c.get("regex", db.Column(db.UnicodeText))

    def check(self, s: str) -> bool:
        return re.match(self.regex, s) is not None


class MIMEFilter(HasRegex, RequestFilter):
    __mapper_args__ = {"polymorphic_identity": "mime"}

    def __init__(self, mime_regex: str, comment: str = None):
        self.regex = mime_regex
        super().__init__(comment=comment)

    def check_request(self, r: Request) -> bool:
        if "file" in r.files:
            return self.check(r.files["file"].mimetype)

        return False

    @property
    def reason(self) -> str:
        return "File MIME type not allowed."


class UAFilter(HasRegex, RequestFilter):
    __mapper_args__ = {"polymorphic_identity": "ua"}

    def __init__(self, ua_regex: str, comment: str = None):
        self.regex = ua_regex
        super().__init__(comment=comment)

    def check_request(self, r: Request) -> bool:
        return self.check(r.user_agent.string)

    @property
    def reason(self) -> str:
        return "User agent not allowed."


class UrlEncoder(object):
    def __init__(self, alphabet, min_length):
        self.alphabet = alphabet
        self.min_length = min_length

    def enbase(self, x):
        n = len(self.alphabet)
        str = ""
        while x > 0:
            str = (self.alphabet[int(x % n)]) + str
            x = int(x // n)
        padding = self.alphabet[0] * (self.min_length - len(str))
        return '%s%s' % (padding, str)

    def debase(self, x):
        n = len(self.alphabet)
        result = 0
        for i, c in enumerate(reversed(x)):
            result += self.alphabet.index(c) * (n ** i)
        return result


su = UrlEncoder(alphabet=app.config["URL_ALPHABET"], min_length=1)


def fhost_url(scheme=None):
    if not scheme:
        return url_for(".fhost", _external=True).rstrip("/")
    else:
        return url_for(".fhost", _external=True, _scheme=scheme).rstrip("/")


def is_fhost_url(url):
    return url.startswith(fhost_url()) or url.startswith(fhost_url("https"))


def shorten(url):
    if len(url) > app.config["MAX_URL_LENGTH"]:
        abort(414)

    if not url_valid(url) or is_fhost_url(url) or "\n" in url:
        abort(400)

    u = URL.get(url)

    return u.geturl()


"""
requested_expiration can be:
    - None, to use the longest allowed file lifespan
    - a duration (in hours) that the file should live for
    - a timestamp in epoch millis that the file should expire at

Any value greater that the longest allowed file lifespan will be rounded down
to that value.
"""
def store_file(f: TransferFile, requested_expiration: typing.Optional[int],
               addr, ua, secret: bool):

    sf, isnew = File.store(f, requested_expiration, addr, ua, secret)

    response = make_response(sf.geturl())
    response.headers["X-Expires"] = sf.expiration

    if isnew:
        response.headers["X-Token"] = sf.mgmt_token

    return response


def store_url(url, addr, ua, secret: bool):
    if is_fhost_url(url):
        abort(400)

    h = {"Accept-Encoding": "identity"}
    r = requests.get(url, stream=True, verify=False, headers=h)

    try:
        r.raise_for_status()
    except requests.exceptions.HTTPError as e:
        return str(e) + "\n"

    if "content-length" in r.headers:
        length = int(r.headers["content-length"])

        if length <= app.config["MAX_CONTENT_LENGTH"]:
            tf = TransferFile(io.BytesIO(r.raw.read()),
                              r.headers["content-type"], "")

            return store_file(tf, None, addr, ua, secret)
        else:
            abort(413)
    else:
        abort(411)


def manage_file(f):
    if request.form["token"] != f.mgmt_token:
        abort(401)

    if "delete" in request.form:
        f.delete()
        db.session.commit()
        return ""
    if "expires" in request.form:
        try:
            requested_expiration = int(request.form["expires"])
        except ValueError:
            abort(400)

        f.expiration = File.get_expiration(requested_expiration, f.size)
        db.session.commit()
        return "", 202

    abort(400)


@app.route("/<path:path>", methods=["GET", "POST"])
@app.route("/s/<secret>/<path:path>", methods=["GET", "POST"])
def get(path, secret=None):
    p = Path(path.split("/", 1)[0])
    sufs = "".join(p.suffixes[-2:])
    name = p.name[:-len(sufs) or None]

    if "." in name:
        abort(404)

    id = su.debase(name)

    if sufs:
        f = File.query.get(id)

        if f and f.ext == sufs:
            if f.secret != secret:
                abort(404)

            if f.removed:
                abort(451)

            fpath = f.getpath()

            if not fpath.is_file():
                abort(404)

            if request.method == "POST":
                return manage_file(f)

            if app.config["FHOST_USE_X_ACCEL_REDIRECT"]:
                response = make_response()
                response.headers["Content-Type"] = f.mime
                response.headers["Content-Length"] = f.size
                response.headers["X-Accel-Redirect"] = "/" + str(fpath)
            else:
                response = send_from_directory(
                    app.config["FHOST_STORAGE_PATH"], f.sha256,
                    mimetype=f.mime)

            response.headers["X-Expires"] = f.expiration
            return response
    else:
        if request.method == "POST":
            abort(405)

        if "/" in path:
            abort(404)

        u = URL.query.get(id)

        if u:
            return redirect(u.url)

    abort(404)


@app.route("/", methods=["GET", "POST"])
def fhost():
    if request.method == "POST":
        for flt in RequestFilter.query.all():
            if flt.check_request(request):
                abort(403, flt.reason)

        sf = None
        secret = "secret" in request.form
        addr = ipaddress.ip_address(request.remote_addr)
        if type(addr) is ipaddress.IPv6Address:
            addr = addr.ipv4_mapped or addr

        if "file" in request.files:
            f = request.files["file"]
            tf = TransferFile(f.stream, f.filename, f.content_type)

            try:
                # Store the file with the requested expiration date
                return store_file(
                    tf,
                    int(request.form["expires"]),
                    addr,
                    request.user_agent.string,
                    secret
                )
            except ValueError:
                # The requested expiration date wasn't properly formed
                abort(400)
            except KeyError:
                # No expiration date was requested, store with the max lifespan
                return store_file(
                    tf,
                    None,
                    addr,
                    request.user_agent.string,
                    secret
                )
        elif "url" in request.form:
            return store_url(
                request.form["url"],
                addr,
                request.user_agent.string,
                secret
            )
        elif "shorten" in request.form:
            return shorten(request.form["shorten"])

        abort(400)
    else:
        return render_template("index.html")


@app.route("/robots.txt")
def robots():
    return """User-agent: *
Disallow: /
"""


@app.errorhandler(400)
@app.errorhandler(401)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(411)
@app.errorhandler(413)
@app.errorhandler(414)
@app.errorhandler(415)
@app.errorhandler(451)
def ehandler(e):
    try:
        return render_template(f"{e.code}.html", id=id, request=request,
                               description=e.description), e.code
    except TemplateNotFound:
        return "Segmentation fault\n", e.code


@app.cli.command("prune")
def prune():
    """
    Clean up expired files

    Deletes any files from the filesystem which have hit their expiration time.
    This doesn't remove them from the database, only from the filesystem.
    It is recommended that server owners run this command regularly, or set it
    up on a timer.
    """
    current_time = time.time() * 1000

    # The path to where uploaded files are stored
    storage = Path(app.config["FHOST_STORAGE_PATH"])

    # A list of all files who've passed their expiration times
    expired_files = File.query\
        .where(
            and_(
                File.expiration.is_not(None),
                File.expiration < current_time
            )
        )

    files_removed = 0

    # For every expired file...
    for file in expired_files:
        # Log the file we're about to remove
        file_name = file.getname()
        file_hash = file.sha256
        file_path = storage / file_hash
        print(f"Removing expired file {file_name} [{file_hash}]")

        # Remove it from the file system
        try:
            os.remove(file_path)
            files_removed += 1
        except FileNotFoundError:
            pass  # If the file was already gone, we're good
        except OSError as e:
            print(e)
            print(
                "\n------------------------------------"
                "Encountered an error while trying to remove file {file_path}."
                "Make sure the server is configured correctly, permissions "
                "are okay, and everything is ship shape, then try again.")
            return

        # Finally, mark that the file was removed
        file.expiration = None
    db.session.commit()

    print(f"\nDone!  {files_removed} file(s) removed")


"""
For a file of a given size, determine the largest allowed lifespan of that file

Based on the current app's configuration:
Specifically, the  MAX_CONTENT_LENGTH, as well as FHOST_{MIN,MAX}_EXPIRATION.

This lifespan may be shortened by a user's request, but no files should be
allowed to expire at a point after this number.

Value returned is a duration in milliseconds.
"""
def get_max_lifespan(filesize: int) -> int:
    min_exp = app.config.get("FHOST_MIN_EXPIRATION", 30 * 24 * 60 * 60 * 1000)
    max_exp = app.config.get("FHOST_MAX_EXPIRATION", 365 * 24 * 60 * 60 * 1000)
    max_size = app.config.get("MAX_CONTENT_LENGTH", 256 * 1024 * 1024)
    return min_exp + int((-max_exp + min_exp) * (filesize / max_size - 1) ** 3)


def do_vscan(f):
    if f["path"].is_file():
        with open(f["path"], "rb") as scanf:
            try:
                res = list(app.config["VSCAN_SOCKET"].instream(scanf).values())
                f["result"] = res[0]
            except:
                f["result"] = ("SCAN FAILED", None)
    else:
        f["result"] = ("FILE NOT FOUND", None)

    return f


@app.cli.command("vscan")
def vscan():
    if not app.config["VSCAN_SOCKET"]:
        print("Error: Virus scanning enabled but no connection method "
              "specified.\nPlease set VSCAN_SOCKET.")
        sys.exit(1)

    qp = Path(app.config["VSCAN_QUARANTINE_PATH"])
    qp.mkdir(parents=True, exist_ok=True)

    from multiprocessing import Pool
    with Pool() as p:
        if isinstance(app.config["VSCAN_INTERVAL"], datetime.timedelta):
            scandate = datetime.datetime.now() - app.config["VSCAN_INTERVAL"]
            res = File.query.filter(or_(File.last_vscan < scandate,
                                        File.last_vscan == None),
                                    File.removed == False)
        else:
            res = File.query.filter(File.last_vscan == None,
                                    File.removed == False)

        work = [{"path": f.getpath(), "name": f.getname(), "id": f.id}
                for f in res]

        results = []
        for i, r in enumerate(p.imap_unordered(do_vscan, work)):
            if r["result"][0] != "OK":
                print(f"{r['name']}: {r['result'][0]} {r['result'][1] or ''}")

            found = False
            if r["result"][0] == "FOUND":
                if not r["result"][1] in app.config["VSCAN_IGNORE"]:
                    r["path"].rename(qp / r["name"])
                    found = True

            results.append({
                "id": r["id"],
                "last_vscan": None if r["result"][0] == "SCAN FAILED"
                else datetime.datetime.now(),
                "removed": found})

        db.session.bulk_update_mappings(File, results)
        db.session.commit()