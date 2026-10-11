#pragma once

// Lets the game load CDLC whose PSARC TOC and SNG charts are stored unencrypted.
// Requires the signature verification patch, since plain SNGs carry a zeroed signature.
bool PatchPlainPsarc();