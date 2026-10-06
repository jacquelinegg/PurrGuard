"""Creates demo_files/ folder with clean and "infected" files (only FAKE keys). Run from root: python tests/make_demo.py"""
import os
import shutil
import subprocess
import sys

import numpy as np
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
subprocess.run([sys.executable, os.path.join(HERE, "make_samples.py")], check=True, capture_output=True)
S, D = "tests/samples/", "demo_files/"
os.makedirs(D, exist_ok=True)
FAKE = b"api_key=AKIAFAKEFAKEFAKE1234 FAKE-DEMO-ONLY"
for src, dst in [("clean.png", "01_logo_clean.png"), ("stego_lsb.png", "02_logo_infected_lsb.png"),
                 ("trailing.png", "03_logo_infected_trailing.png"), ("chunk.png", "04_logo_infected_chunk.png"),
                 ("clean.sql", "09_users_clean.sql"), ("migration.sql", "10_users_infected.sql"),
                 ("clean.wav", "11_audio_clean.wav"), ("stego.wav", "12_audio_infected.wav")]:
    shutil.copy(S + src, D + dst)

arr = np.array(Image.open(S + "clean.png").convert("RGB"))
Image.fromarray(arr).save(D + "05_photo_clean.jpg", quality=90)
shutil.copy(D + "05_photo_clean.jpg", D + "06_photo_infected.jpg")
open(D + "06_photo_infected.jpg", "ab").write(FAKE)


def pdf(infected):
    def stream(data, extra=b""):
        return b"<< " + extra + b" /Length " + str(len(data)).encode() + b" >>\nstream\n" + data + b"\nendstream"
    cat = b"<< /Type /Catalog /Pages 2 0 R"
    if infected:
        cat += b" /Names << /EmbeddedFiles << /Names [(note.txt) 6 0 R] >> >> /OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >>"
    objs = {1: cat + b" >>", 2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
            4: stream(b"BT /F1 24 Tf 72 700 Td (Quarterly report) Tj ET"), 5: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"}
    if infected:
        objs[6] = b"<< /Type /Filespec /F (note.txt) /EF << /F 7 0 R >> >>"
        objs[7] = stream(FAKE, b"/Type /EmbeddedFile")
    out, offs = b"%PDF-1.4\n", {}
    for n in sorted(objs):
        offs[n] = len(out)
        out += f"{n} 0 obj\n".encode() + objs[n] + b"\nendobj\n"
    x = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    out += b"".join(f"{offs[n]:010d} 00000 n \n".encode() for n in sorted(objs))
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{x}\n%%EOF\n".encode()
    return out + (b"%" + FAKE + b"\n" if infected else b"")


open(D + "07_report_clean.pdf", "wb").write(pdf(False))
open(D + "08_report_infected.pdf", "wb").write(pdf(True))

a = np.array(Image.open(D + "01_logo_clean.png").convert("RGB")).astype(int)
b = np.array(Image.open(D + "02_logo_infected_lsb.png").convert("RGB")).astype(int)
open(D + "README.txt", "w", encoding="utf-8").write(f"""TEST FILES FOR PURRGUARD (all keys are FAKE)

Clean: 01, 05, 07, 09, 11        Infected: 02, 03, 04, 06, 08, 10, 12

01 vs 02  PNG with hidden text in the least significant bits. The maximum pixel difference is {int(abs(a - b).max())} out of 255,
          i.e. the eye sees nothing. It is caught only with statistics.
03        PNG with data appended after the end of the file (looks normal in any image viewer).
04        PNG with hidden text in a metadata chunk.
05 vs 06  JPEG with data appended after the end.
07 vs 08  PDF: the infected one has data after %%EOF, embedded file, and script on open.
09 vs 10  SQL: the infected one looks identical but contains hundreds of invisible Unicode characters.
11 vs 12  WAV: the infected one has a non-standard chunk with data.

How to prove to the jury that the file is truly infected:
  python main.py explain demo_files/*     # what exactly is detected, where, and how to verify it with strings/xxd/grep
Compare the clean and infected file: same kind, different size or structure.
""")
print("Done:", sorted(os.listdir(D)))
