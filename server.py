#!/usr/bin/env python3
"""server.py -- local web page: upload a CycloneDX SBOM, get the dashboard.

  python server.py
  python server.py --port 8080

Opens on http://127.0.0.1:8000 by default. Stdlib only -- no framework
to install, nothing to configure. Each upload runs in its own temporary
folder; the folder (and the uploaded file) is deleted once the response
is sent, so nothing from an upload is kept on disk afterward.

Uses ThreadingHTTPServer so two uploads handled at once get separate
temp directories and cannot see each other's files.

Why this doesn't use Python's cgi module for the upload form: cgi was
removed from the standard library in Python 3.13. This parses the
multipart/form-data body itself instead (one field, one file -- a small,
bounded problem, not worth a dependency).
"""
import argparse
import html
import shutil
import sys
import tempfile
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import run_pipeline
import build_dashboard

MAX_UPLOAD_BYTES = 25 * 1024 * 1024  # 25 MB: generous for a JSON SBOM, small enough to refuse abuse

PAGE_CSS = """
:root{--teal:#157A6E;--slate:#55636F;--red:#B83A4B}
*{box-sizing:border-box}
body{margin:0;font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:#1f2d33;background:#fff}
main{max-width:640px;margin:60px auto;padding:0 20px}
h1{font-size:1.5rem;margin:0 0 6px}
p.lede{color:var(--slate);margin:0 0 28px}
.drop{border:2px dashed #D6D6D6;border-radius:10px;padding:34px 20px;text-align:center}
input[type=file]{margin:10px 0}
button{background:var(--teal);color:#fff;border:0;padding:10px 22px;border-radius:6px;font:inherit;font-size:1rem;cursor:pointer}
button:hover{opacity:.92}
.err{background:#FBEDEF;border-left:4px solid var(--red);padding:12px 16px;border-radius:6px;margin:0 0 20px;color:#7a2230}
.note{color:var(--slate);font-size:.9rem;margin-top:18px}
"""

UPLOAD_FORM = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SBOM coverage - upload</title><style>%s</style></head>
<body><main>
<h1>SBOM coverage checker</h1>
<p class="lede">Upload a CycloneDX JSON SBOM. The file is scanned, classified, and shown to you -- it is not kept afterward.</p>
%s
<form class="drop" method="post" action="/upload" enctype="multipart/form-data">
  <div>Choose a CycloneDX JSON file (from Syft or any other tool that exports it)</div>
  <input type="file" name="sbom" accept=".json,application/json" required>
  <div><button type="submit">Scan it</button></div>
</form>
<p class="note">This runs Grype locally and does not send your file anywhere else. Nothing you upload is stored once the page below is shown.</p>
</main></body></html>"""


def render_error(message):
    body = '<div class="err"><b>Couldn\'t process that file.</b><br>%s</div>' % html.escape(message)
    return (UPLOAD_FORM % (PAGE_CSS, body)).encode("utf-8")


def parse_multipart(body, boundary):
    """Minimal multipart/form-data parser for one file field. Returns
    (filename, content_bytes) for the first file part found, or None.

    Strips exactly one leading and one trailing CRLF per part -- the
    multipart spec guarantees exactly those two, as framing around the
    boundary marker. A blind .strip(b"\\r\\n") is wrong here: for an empty
    uploaded file the body between the header blank line and the boundary
    is itself just a lone CRLF, and a blind strip eats that separator too,
    making the part look headerless and silently dropping it."""
    marker = b"--" + boundary
    parts = body.split(marker)
    for part in parts:
        if not part or part.startswith(b"--"):
            continue  # empty preamble, or the final "--" end marker
        if part.startswith(b"\r\n"):
            part = part[2:]
        if part.endswith(b"\r\n"):
            part = part[:-2]
        if b"\r\n\r\n" not in part:
            continue
        head, _, data = part.partition(b"\r\n\r\n")
        head_text = head.decode("utf-8", "replace")
        if "filename=" not in head_text:
            continue  # a non-file form field; not expected here, skip it
        # pull filename="..." out of the Content-Disposition header
        try:
            fname = head_text.split("filename=", 1)[1].split('"')[1]
        except IndexError:
            fname = "upload"
        if not fname:
            return None  # an <input type=file> submitted with nothing chosen
        return fname, data
    return None


class Handler(BaseHTTPRequestHandler):
    server_version = "SBOMCoverage/0.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def do_GET(self):
        if self.path not in ("/", "/index.html"):
            self.send_response(404)
            self.end_headers()
            return
        body = (UPLOAD_FORM % (PAGE_CSS, "")).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/upload":
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", 0))
        if length <= 0:
            return self._respond(400, render_error("No file was received."))
        if length > MAX_UPLOAD_BYTES:
            return self._respond(400, render_error(
                "That file is larger than this demo accepts (25 MB limit)."))

        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type or "boundary=" not in content_type:
            return self._respond(400, render_error("Unexpected form submission."))
        boundary = content_type.split("boundary=", 1)[1].strip().strip('"').encode("utf-8")

        body = self.rfile.read(length)
        found = parse_multipart(body, boundary)
        if not found:
            return self._respond(400, render_error("Choose a file before clicking Scan."))
        filename, data = found

        # Each request gets its own temp directory, so two uploads handled
        # at the same time (ThreadingHTTPServer) never share files, and the
        # uploaded file never keeps its original name on disk.
        tmpdir = Path(tempfile.mkdtemp(prefix="sbomcov-"))
        try:
            sbom_path = tmpdir / "upload.json"
            sbom_path.write_bytes(data)
            outdir = tmpdir / "out"
            try:
                result = run_pipeline.run(sbom_path, outdir)
            except run_pipeline.PipelineError as e:
                return self._respond(400, render_error(str(e)))
            except Exception:
                traceback.print_exc()
                return self._respond(500, render_error(
                    "Something went wrong while scanning this file. "
                    "It may be valid JSON but structured in a way this tool doesn't expect."))

            title = Path(filename).stem or "Uploaded SBOM"
            page = build_dashboard.build(outdir, title)
            self._respond(200, page.encode("utf-8"))
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def _respond(self, code, body_bytes):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)


def main():
    ap = argparse.ArgumentParser(description="Local SBOM-coverage upload page.")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print("SBOM coverage checker running at http://%s:%d  (Ctrl+C to stop)"
          % (args.host, args.port))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
        srv.shutdown()


if __name__ == "__main__":
    main()
