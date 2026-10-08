DEMO FILES FOR PURRGUARD (all keys are FAKE)

Clean: 01, 05, 07, 09, 11        Infected: 02, 03, 04, 06, 08, 10, 12

01 vs 02  PNG with hidden text in the least significant bits. The biggest pixel difference is 1 out of 255,
          i.e. the eye sees nothing. Caught only by statistics.
03        PNG with data appended after the end of the file (looks normal in any image viewer).
04        PNG with hidden text in a utility chunk.
05 vs 06  JPEG with data appended after the end.
07 vs 08  PDF: the infected one has data after %%EOF, an embedded file, and a script on open.
09 vs 10  SQL: the infected one looks the same but contains hundreds of invisible Unicode characters.
11 vs 12  WAV: the infected one has a non-standard chunk with data.

How to prove to the jury that the file is really defective:
  python main.py explain demo_files/*     # exactly what was found, where, and how to verify it with strings/xxd/grep
Compare the clean and infected file: same look, different size or structure.
