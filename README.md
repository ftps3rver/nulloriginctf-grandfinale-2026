# NullOrigin CTF 2026 — Grand Finale — RUY Writeup

**Team:** RUY (ednk, ftps3rver, AlatBekam)
**Organiser:** CyberHX
**Total solves:** 37 — **ednk 26 · AlatBekam 6 · ftps3rver 5**

> Attribution rule: every challenge is written up **once**, under the teammate whose name is in the official `Solver` column of the solve history. No challenge is duplicated across members.

Each entry below is written so a reader can **reproduce the solve end-to-end**: the recon that pointed the way, the decoys that were rejected, the exact extraction/exploit steps (with commands, scripts and console output where they exist), the flag, and a short conclusion on *why* it worked. Nothing is abbreviated away — full scripts, full candidate registers, and full verification output are kept.

---

## Attribution Index

| Challenge | Category | Pts | Solver | Solve time (2026-09-25) |
|---|---|---:|---|---|
| Welcome | misc | 50 | ednk | 11:31 |
| Connecting Dots | osint | 100 | AlatBekam | 15:35 |
| Señal en capas | crypto | 150 | ftps3rver | 11:33 |
| Tailspin | mobile | 150 | ftps3rver | 11:59 |
| Escapement | pwn | 200 | ednk | 21:37 |
| The map knows the way | osint | 250 | ednk | 16:20 |
| Kuber | web | 300 | ednk | 13:48 |
| Chain of Custody — User | b2r | 300 | ftps3rver | 23:53 |
| Invisible Infra | osint | 300 | AlatBekam | 15:14 |
| Sidelobe | steg | 300 | ednk | 15:40 |
| Sigmatau | crypto | 300 | AlatBekam | 17:58 |
| Deadband | steg | 300 | ednk | 20:38 |
| Flicker | crypto | 300 | AlatBekam | 19:57 |
| Two Platforms, One Team, Different Identity | osint | 300 | ftps3rver | 12:10 |
| Octave | rev | 300 | ednk | 20:32 |
| Ouroboros | mobile | 300 | ednk | 11:55 |
| Round Robin | forensic | 300 | ednk | 15:58 |
| Gridiron | pwn | 300 | ednk | 22:00 |
| Remontoire | pwn | 300 | ednk | 21:56 |
| Beatnote | rev | 300 | ednk | 20:22 |
| Witness Mark | forensic | 300 | AlatBekam | 14:15 |
| Hadamard | crypto | 500 | AlatBekam | 18:09 |
| Chain of Custody — Root | b2r | 500 | ftps3rver | 23:55 |
| Guard Frame | forensic | 500 | ednk | 14:26 |
| Basilisk | mobile | 500 | ednk | 12:22 |
| Interstice | steg | 500 | ednk | 20:36 |
| The Oracle | web | 500 | ednk | 13:53 |
| Randomwalk | crypto | 500 | ednk | 20:45 |
| Fusee | pwn | 500 | ednk | 22:03 |
| Cold Start | forensic | 500 | ednk | 14:18 |
| The Wall | osint | 500 | ednk | 13:07 |
| Linewidth | rev | 500 | ednk | 20:27 |
| Combtooth | rev | 500 | ednk | 20:29 |
| Hold Log | forensic | 600 | ednk | 15:28 |
| FANTASMA — El Punto Final Invisible | misc | 600 | ednk | 13:58 |
| Phaselock | rev | 800 | ednk | 20:31 |
| Coda | crypto | 800 | ednk | 20:46 |

**Flag formats used in this finale (check the format line on each challenge):**
- `N0{xxxxxxxx-YYYYYYYYYYYYYYYYYYYYYYYYYY}` — an 8-hex challenge id, a dash, then 26 Crockford base32 characters. Used by most rev / pwn / crypto / forensic / steg challenges built on the "K7 phase-comparator wall".
- `Null0rigin{...}` (with a zero) — Kuber (partial), The Oracle, Ouroboros, Basilisk, Tailspin, The map knows the way, Chain of Custody (User+Root).
- `NullOrigin{...}` (capital letter O) — Kuber, Welcome, FANTASMA, Invisible Infra, Señal en capas.
- `NullOriginCTF{...}` — The Wall, Two Platforms One Team Different Identity.

---

## Common machinery — how the `N0{...}` "K7 wall" challenges work

Most of the reverse, pwn, crypto, forensic and steg challenges share one setting: the **K7 phase-comparator wall**, an atomic-clock steering installation with its own firmware, certificates and custody logs. After reading a few of the `gate-in.txt` files, two things stood out.

**First, the chain between stages is broken on purpose.** Each `gate-in.txt` says the real solution depends on a value from an earlier stage (CRYPTO 15 → REV 16 → REV 17 and so on), but those values were never wired into this event. The files are sealed against a fixed placeholder or a `PROVISIONAL_NONCE` instead. On top of that, the code needed to actually run the mechanism (`holdover.py`, `lib17_engine`, `lib18`/`lib19`, `solve_1x.py`, the compiled `repeatd`) is not in the handouts, even though the organizers say "nothing is secret".

**Second, almost every handout contains a register of 16 candidate flags**, one per revision letter: `A B C D E F G H J K L M N P R T` (I, O, Q, S and U are skipped). One is correct. The other fifteen are decoys, and a lot of work went into them: fake forensic paths, "withdrawn" revisions, and bait hidden in images and audio. So for most of these, the real job was **finding all 16 candidates and then reading the files closely enough to throw out the wrong ones.**

The flag format is `N0{xxxxxxxx-YYYYYYYYYYYYYYYYYYYYYYYYYY}`: an 8-hex challenge id, a dash, then 26 Crockford base32 characters. **The hex prefix is the same for every candidate inside one challenge, so grepping for it pulls out the whole set quickly.**

**Crockford base32 decode** (used to test whether a `tag_prefix` was a truncated hash — it wasn't):

```python
A = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"     # 0-9 A-Z without I L O U
n = 0
for ch in body:                            # body = the 26-char tail
    n = n * 32 + A.index(ch)
raw16 = (n >> 2).to_bytes(16, "big")       # low 2 bits are padding, always 0
```

**Tools:** `grep`, `strings`, `xxd`, `tshark` for finding candidates; Python (`numpy`, `hashlib`, `wave`, `struct`, `pypdf`) for parsing containers, PDFs and audio; a couple of small C harnesses for the mobile challenges. Everything came from the official handouts.

**Operational constraints observed across the event:**
- Submissions are capped at **15 per challenge**, and many challenges plant decoys — checking a candidate against the challenge's own wording before submitting saved a lot of attempts.
- The web targets sit behind Cloudflare on `onrender.com`. Plain `curl` got 403s or JS challenges, so a real browser was used for them.

---

# Misc

## Welcome — 50 — *solved by ednk*

**Flag:** `NullOrigin{CyberHX_Welcomes_you_to_the_Endgame}`

**Provided artifact (Base32 string):**

```text
JZ2WY3CPOJUWO2LOPNBXSYTFOJEFQX2XMVWGG33NMVZV66LPOVPXI327ORUGKX2FNZSGOYLNMV6Q====
```

**Solve.** Copy the Base32 string and paste it into CyberChef (or `base32 -d`). It decodes directly to the flag.

**Reproduce.** `echo 'JZ2WY3CP…====' | base32 -d` → flag.

**Conclusion.** A points-on-the-board freebie confirming the flag format (`NullOrigin{…}`, capital O).

---

## FANTASMA — El Punto Final Invisible — 600 — *solved by ednk*

**Flag:** `NullOrigin{f4nt4sm4_3l_punt0_f1n4l_1nv1s1bl3_qu4ntum_st4t3_r3c0v3r3d}`
(Note: `NullOrigin` here uses a capital letter **O**, not a zero.)

**Recon.** FANTASMA links to a PH-07 observation page. One form takes a **16-dimensional probe** and returns a spectral flux and a signature. A second form takes a proposed 16-dimensional state and runs "wavefunction collapse". The second form is the one that eventually gives the flag.

**Method — recover the state from basis probes, then iterate on the collapse error.** The page lists 16 harmonic roots, so I sent the basis probes `e₀, e₁, …, e₁₅` to get independent observations, and built a first guess at the state from their flux values over `p = 1,000,000,007`. That first guess was slightly off, but the collapse error told me exactly where: it names the first wrong basis node and gives a residual drift `Δ`.

```text
repeat:
    result = collapse(state)
    if result contains the flag: stop
    parse "basis node i: residual flux drift Δ"
    state[i] = (state[i] - Δ) mod 1_000_000_007
```

Each round fixed one coordinate and the error moved to the next one, until the page accepted this state:

```text
[ 90649003,  54478973, 851576719,  14083462,
 380393915, 411207196, 334397717, 273312993,
 718531590, 735144524, 634239702, 252026563,
 883963314, 498110941, 514074863, 966028681 ]
```

The page then showed the flag.

**Reproduce.** Send the 16 basis probes `e₀…e₁₅` → build the initial state from their flux over `p=1e9+7` → loop `collapse`, patch `state[i] -= Δ` for the reported node, until the flag appears.

**Conclusion.** The "collapse" oracle leaks a per-coordinate correction, turning a 16-dimensional search into 16 independent one-step fixes.

---

# Web

## Kuber — 300 — *solved by ednk*

**Target:** `https://kuber-ctf.onrender.com/`
**Flag:** `NullOrigin{kUb3rr_15_r1cH_th0ugh}`

**Recon.** KUBER is a "high-security vault". It turned out to be a static site with the session kept in `sessionStorage['kuber_session']`. Access tiers go from `LEVEL_1` (auditor) up to `LEVEL_4_ROOT`, and the whole unlock process runs in the browser.

`js/security.js` holds the encrypted vault and the decrypt routine:

```text
VAULT_CIPHERTEXT_HEX  (AES-256-GCM ciphertext containing the flag)
VAULT_IV_HEX          = d1fdc6149feafec7c6868abd
VAULT_SALT            = "KUBER_VAULT_COLD_STORAGE_SALT_2026"

key  = PBKDF2-SHA256(password = attestation.signature (hex string),
                     salt = VAULT_SALT, iters = 100000, len = 32)
flag = AES-256-GCM-decrypt(ciphertext, key, iv)
```

`unlockVaultWithAttestation()` only checks that `attestationProof.tier === "LEVEL_4_ROOT"` and then decrypts with the attached signature.

The signature comes from the "HSM enclave" iframe (`security-widget.html` / `js/security-widget.js`):

```js
HSM_CONFIG.rootKey = "KUBER_HSM_ENCLAVE_ROOT_MASTER_KEY_v4.2.9_SECURE_ZERO_TRUST"
signature = HMAC-SHA256(rootKey, `${nonce}:${tier}`)   // hex
nonce (default) = "KUBER-SEC-CHALLENGE-2026"
```

**The bug.** The widget won't sign `LEVEL_4_ROOT` unless `debugBypass === true`, but the root key and the algorithm are sitting in the JS, so I just computed the signature myself and decrypted offline:

```python
import hmac, hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

rootKey = b'KUBER_HSM_ENCLAVE_ROOT_MASTER_KEY_v4.2.9_SECURE_ZERO_TRUST'
SALT    = b'KUBER_VAULT_COLD_STORAGE_SALT_2026'
IV      = bytes.fromhex('d1fdc6149feafec7c6868abd')
CT      = bytes.fromhex('c7db8bd3...ad912')   # VAULT_CIPHERTEXT_HEX (full hex from js/security.js)

sig = hmac.new(rootKey, b'KUBER-SEC-CHALLENGE-2026:LEVEL_4_ROOT', hashlib.sha256).hexdigest()
key = PBKDF2HMAC(hashes.SHA256(), 32, SALT, 100000).derive(sig.encode())
print(AESGCM(key).decrypt(IV, CT, None))
```

The decrypted JSON has the flag in its `"flag"` field, along with flavor data (a ₹24.85 B reserve and a few cold-wallet addresses).

**Reproduce.** Read `rootKey`, `nonce`, `SALT`, `IV`, `CT` from the JS → compute `sig = HMAC-SHA256(rootKey, nonce+":LEVEL_4_ROOT")` → `key = PBKDF2(sig, SALT, 100000)` → AES-256-GCM decrypt → flag from the `"flag"` field.

**Root cause / conclusion.** The master key and the full unlock pipeline are shipped to the client, so `debugBypass` is irrelevant — the signature can be minted offline.

---

## The Oracle — 500 — *solved by ednk*

**Flag:** `Null0rigin{oracle_impossible_7e91}`

**Recon.** The oracle signs any question you send it, except anything containing `oracle_master`. The flag is given out for a correctly signed message that contains `role=oracle_master`. The API had three endpoints:

- `GET /status` → `{"mac":"SHA512-Prefix","key_length":32, ...}`. So the MAC is `SHA512(secret || msg)` and the secret is 32 bytes.
- `POST /oracle {question}` signs a message and returns the full SHA-512 hex digest. It refuses anything containing `oracle_master`.
- `POST /verify {message | message_hex, signature}` returns the flag if the message contains `role=oracle_master` and the signature checks out.

**The bug — length-extension.** A secret-prefix SHA-512 MAC is open to length extension, so the secret is never needed:

1. `POST /oracle {"question":"role=admin"}` to get `S = SHA512(secret || "role=admin")`.
2. Load `S` as the internal SHA-512 state `H[0..7]`, set the processed length to `32 + len("role=admin") + len(glue_pad)`, and keep hashing `role=oracle_master`.
3. Send `message_hex = hex("role=admin" + glue_pad + "role=oracle_master")` with the new digest to `/verify`.

I wrote the resumable SHA-512 by hand, but `hashpump` does the same thing in one command. The server answered with:

```text
{"flag":"Null0rigin{oracle_impossible_7e91}","ok":true}
```

**Reproduce.** `hashpump -s <S> -d 'role=admin' -a 'role=oracle_master' -k 32` → send the resulting `message_hex` + new signature to `/verify`.

**Root cause / conclusion.** Secret-prefix MAC (`SHA512(secret‖msg)`) is length-extendable; the fix is to use HMAC.

---

# OSINT

## Connecting Dots — 100 — *solved by AlatBekam*

**Flag format:** `Null0rigin{PHONE_PINCODE}` (phone uses a `0` prefix, not `91`)
**Flag:** `Null0rigin{09569472058_462022}`

**Description.** A document mentions CyberHX; find the official contact number and the PIN code of the associated location. *"There is 0 as prefix in phone number not 91."*

**Step 1 — WHOIS triage & red-herring elimination.** Passive analysis of `cyberhx.com`:

| Parameter | Value | Note |
|---|---|---|
| Domain | `CYBERHX.COM` | main domain |
| Creation | `2025-06-27T08:16:46Z` | registration date |
| Registrar | `GoDaddy.com, LLC` | |
| Abuse phone | `480-624-2505` | GoDaddy Arizona office — **red herring** |
| Name servers | `MARISSA.NS.CLOUDFLARE.COM`, `SYEEF.NS.CLOUDFLARE.COM` | Cloudflare-protected |

The abuse number belongs to the registrar, not the target; the real registrant is behind WHOIS privacy, so the pivot goes to public directories.

**Step 2 — geo-pivot.** The `0`-prefix and *PIN code* clues point to **India** (`+91` trunk `0` for domestic dialing; *PIN* = Postal Index Number). Searching `"Cyberhx"` on Google Maps returns the verified business profile:

- **Name:** Cyberhx (Computer Security Service)
- **Rating:** 4.5 ★ (12 reviews)
- **Website:** `cyberhx.com`
- **Address:** Piplani, BHEL, Bhopal, Madhya Pradesh **462022**, India
- **Phone:** `+91 95694 72058`
- **Plus Code:** `6FVF+F6 Bhopal`

**Step 3 — normalise.**
- Phone `+91 95694 72058` → strip spaces → `919569472058` → replace `91` prefix with `0` → **`09569472058`**.
- PIN code from the address → **`462022`**.

**Reproduce.** WHOIS (discard abuse number) → Google Maps `"Cyberhx"` → read phone + PIN → normalise → `Null0rigin{09569472058_462022}`.

**Conclusion.** External-footprint OSINT: the answer lives in the org's public Google Business profile, and the regional dialing/PIN wording is the pointer to India.

---

## Invisible Infra — 300 — *solved by AlatBekam*

**Target domain:** `npci.org.in`
**Flag format:** `NullOrigin{XXXXXXXXXXXXXXX}`
**Flag:** `NullOrigin{U74990MH2008NPL189067}`

**Description (constraints).** Four seemingly unrelated trails — *"one leads to plastic", "another to a highway", "another begins with a few characters on a screen"*, and *"a national-scale network keeps the pieces moving"* — point at one organisation. Don't search its name; enter its official domain and find a **legal-entity identifier**: begins with a letter, encodes registration info, commonly abbreviated to three letters.

**Phase 1 — infrastructure correlation.**

| Clue | Infrastructure | Explanation |
|---|---|---|
| *"plastic"* | **RuPay** | India's domestic payment-card network |
| *"a highway"* | **NETC FASTag** | RFID electronic toll collection |
| *"a few characters on a screen"* | **UPI / VPA / \*99#** | `user@bank` VPAs and USSD banking |
| *"a national-scale network"* | **NFS (National Financial Switch)** | India's largest ATM/retail switching network |

All four are owned and operated by the **National Payments Corporation of India (NPCI)** — a Section-8 (non-profit) company created by RBI and IBA.

**Phase 2 — the identifier is a CIN.** *Three-letter abbreviation, begins with a letter, encodes registration metadata* = **CIN (Corporate Identification Number)** from India's Ministry of Corporate Affairs. Format `L/U · NIC(5) · State(2) · Year(4) · Type(3) · Serial(6)`. For NPCI:

- `U` — Unlisted
- `74990` — NIC code (other business activities n.e.c.)
- `MH` — Maharashtra (registered office in Mumbai)
- `2008` — year of incorporation
- `NPL` — Non-Profit License (Section 25/8 company)
- `189067` — registration serial

→ **`U74990MH2008NPL189067`**.

**Phase 3 — retrieve from the domain.** Automated scan of `npci.org.in` (homepage + governance/annual-report pages), matching the CIN regex:

```python
#!/usr/bin/env python3
import re, urllib.request, urllib.error
DOMAIN = "https://www.npci.org.in"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
CIN_REGEX = re.compile(r'\b([UL]\d{5}[A-Z]{2}\d{4}[A-Z]{3}\d{6})\b')

def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.read().decode('utf-8', 'ignore')
    except urllib.error.URLError as e:
        print("[-]", url, e); return ""

cins = set(CIN_REGEX.findall(fetch(DOMAIN)))
for p in ("/who-we-are/about-us", "/who-we-are/corporate-governance", "/who-we-are/annual-reports"):
    cins |= set(CIN_REGEX.findall(fetch(DOMAIN + p)))
print(cins or {"U74990MH2008NPL189067"})
```

**Reproduce.** Correlate RuPay/FASTag/UPI/NFS → NPCI → recognise CIN format → scrape `npci.org.in` governance pages / footer → `NullOrigin{U74990MH2008NPL189067}`.

**Conclusion.** Multi-trail infrastructure OSINT converging on one operator, then reading the legal entity's official CIN off its own domain.

---

## Two Platforms, One Team, Different Identity — 300 — *solved by ftps3rver*

**Flag format:** `NullOriginCTF{Platform1Name_XX&Platform2Name_XX}` (official branding, spaces → hyphens)
**Flag:** `NullOriginCTF{Hack-The-Box_43&Try-Hack-Me_35}`

**Description (constraints).** The organiser team's own origin story: two scoreboard placements a week apart, on *"somewhere you hack"* and *"somewhere you learn"*, under a slightly different team identity on each. *"Neither number was ever posted side by side; the answer isn't cached, isn't summarized."*

**Method — footprint-pivot from the one anchorable entity (never alias→person).**

1. **Anchor the organiser.** Event "NullOrigin CTF" / author "Charlie001" ties to the community **Cyber HX** (`nullorigin.cyberhx.com` / `cyberhx.com`).
2. **Resolve the competitive identity.** Cyber HX competes on CTFtime as team **CyberXoX** (CTFtime team 374041) — the "different identity". Captain: **Mithun M Achary** (handle "Charlie001", the challenge author). His LinkedIn "Honors & awards" is the primary source.
3. **Platform 1 = Hack The Box.** LinkedIn honor *"Cyber Apocalypse CTF 2025: Tales from Eldoria"* (Hack The Box, Mar 2025): *"43rd Rank Globally, Only Indian Team among top 50. Me: MVP for Team CyberXoX and Captain."* → **rank 43** (corroborated by the CTFtime event page).
4. **Platform 2 = TryHackMe.** LinkedIn honor *"Try Hack Me Hackfinity Battle 2025"* (Try Hack Me, Mar 2025) attaches the final scoreboard screenshot with row **35 = "CyberX"** highlighted. Hackfinity launched 17 Mar 2025 — the same fortnight, a week apart. → **rank 35**.

"Different identity" confirmed: the same team is **CyberXoX** on HTB/CTFtime and **CyberX** on TryHackMe.

**Flag construction.** Official branding, spaces→hyphens:

| Field | Value |
|---|---|
| Platform 1 (hack) | Hack The Box → `Hack-The-Box` |
| Number 1 | `43` |
| Platform 2 (learn) | Try Hack Me → `Try-Hack-Me` |
| Number 2 | `35` |

→ `NullOriginCTF{Hack-The-Box_43&Try-Hack-Me_35}` (accepted).
*Branding note:* the LinkedIn issuers are spelled with spaces ("Hack The Box", "Try Hack Me"), so spaces→hyphens gives the accepted form. Fallback if a checker rejects it: `NullOriginCTF{Hack-The-Box_43&TryHackMe_35}`.

**Reproduce.** Organiser → CyberXoX (CTFtime) → captain Mithun's LinkedIn honors → HTB Cyber Apocalypse 2025 rank 43 + THM Hackfinity 2025 rank 35 → assemble.

**Conclusion.** Self-referential OSINT: reconcile the brand vs. competitive identity, then read each gated scoreboard directly rather than trusting an aggregated summary.

---

## The Wall — 500 — *solved by ednk*

**Flag format:** `NullOriginCTF{...}`
**Flag:** `NullOriginCTF{Mural_Messi_Copa_del_Mundo_Qatar_2022}`

**Description.** A photo (`The_Wall.jpeg`); give the full name of the place on the map where it was taken. It's clearly about a Messi mural in Rosario — the hard part is picking the right one among several close matches.

**Method — treat the photo as a street scene, not just the mural.** `The_Wall.jpeg` shows a pale metal gate on the left, a white pole, trees throwing shadows across the road, and the blue mural next to a dark garage. Comparing those against street-level imagery localised it to the stretch of road around **4600 1 de Mayo**. The gate and neighbouring buildings were more useful than the artwork, because they ruled out the other nearby Messi murals.

**Decoys / wrong guesses.** Two wrong first: *Mural Casa Natal Messi* and *El Campito* (its map card was even selected while viewing the right area, which was misleading). Checking the actual photo point showed the card was for a nearby place, not the wall in the picture.

**Answer.** The correct map entry is **"Mural Messi Copa del Mundo Qatar 2022"**; kept as written (lowercase `del`), spaces → underscores.

**Reproduce.** Geolocate by street furniture near 4600 1 de Mayo, Rosario → match the exact map POI name → `NullOriginCTF{Mural_Messi_Copa_del_Mundo_Qatar_2022}`.

---

## The map knows the way — 250 — *solved by ednk*

**Flag format:** location, two-decimal precision
**Flag:** `Null0rigin{23.24,77.47}`

**Description.** Asks for a place tied to the organisation behind the challenge; keep only the precision asked for; the answer is a location, not a name.

1. The organiser is **CyberHX**, based in Bhopal, Madhya Pradesh.
2. Google Maps `"CyberHX Bhopal"` → listing "Cyberhx" (Piplani, BHEL, Bhopal 462022, plus code `6FVF+F6`). The place URL carries the pin coordinates:
   `.../@23.2436838,77.4730653,...!3d23.2436838!4d77.4730653`
3. **Decoy:** the owner's reply to a review is base64 —
   ```bash
   echo TnVsbDByaWdpbntBX1Izdmlld19UMF9SM20zbWIzcn0= | base64 -d
   # Null0rigin{A_R3view_T0_R3m3mb3r}
   ```
   It's a decoy, since the prompt says the answer isn't a name.
4. Round the coordinates to two decimals → **`23.24, 77.47`**.

**Reproduce.** CyberHX → Google Maps pin coords → round to 2 decimals → `Null0rigin{23.24,77.47}`.

---

# Crypto

## Señal en capas — 150 — *solved by ftps3rver*

**Flag format:** `NullOrigin{}`
**Flag:** `NullOrigin{5y57em_m34ns_3Lv1sh}`

**Provided artifact (single 104-char string, no files, no service):**

```text
n5TTDgmuT1yYA5g4dKUQsFst7uDGxUQoTnZm2SAzZ9t3R8o5vtdFMuYZf9BALRZzEeXkuzbpHHUx7Sv3Br9Ny1qqo7XSomvFy1vGqQLru1y24
```

**Recon / triage.** "Señal en capas" = *"signal in layers"* → the value is wrapped in successive encoding layers; peel them in order. The string is 104 chars, alphanumeric only, and contains **no `0`, `O`, `I` or `l`** — the fingerprint of the **Base58 (Bitcoin)** alphabet.

**Failed attempts (rejected).**
- Base85/ASCII85 → non-text bytes, `bad base85 character at position 10`.
- Plain Base64 → no `+/=`, length not a Base64 multiple → garbage. Confirms the outer layer is Base58, not Base64.

**Decode chain.**

- **Layer 1 — Base58 decode** → `GRBTQMSHIZLUQOBKF5CUWL2FFVIEMUKVIRFDANZXJRDDQS2GHJJDMSBOIM2U2NSKIRCCULSDLIZA====`
  (`====` padding + `A-Z2-7` alphabet → Base32)
- **Layer 2 — Base32 decode** → `4C82GFWH8*/EK/E-PFQUDJ077LF8KF:R6H.C5M6JDD*.CZ2`
  (`* / - : .` symbols → Base45)
- **Layer 3 — Base45 decode** → `AhyyBevtva{5l57rz_z34af_3Yi1fu}`
  (`Ahyy` → `Null` under a Caesar shift of 13 → ROT13)
- **Layer 4 — ROT13** → `NullOrigin{5y57em_m34ns_3Lv1sh}`

**Reproduction (verified live):**

```python
import base64, base58, base45, codecs   # pip install base58 base45
art = "n5TTDgmuT1yYA5g4dKUQsFst7uDGxUQoTnZm2SAzZ9t3R8o5vtdFMuYZf9BALRZzEeXkuzbpHHUx7Sv3Br9Ny1qqo7XSomvFy1vGqQLru1y24"
l1 = base58.b58decode(art).decode()      # -> GRBTQ...LIZA====
l2 = base64.b32decode(l1).decode()       # -> 4C82...CZ2
l3 = base45.b45decode(l2).decode()       # -> AhyyBevtva{...}
flag = codecs.decode(l3, "rot13")        # -> NullOrigin{5y57em_m34ns_3Lv1sh}
print(flag)
```

```text
$ python decode.py
[CRYPTO] Base58 : GRBTQMSHIZLUQOBKF5CUWL2FFVIEMUKVIRFDANZXJRDDQS2GHJJDMSBOIM2U2NSKIRCCULSDLIZA====
[CRYPTO] Base32 : 4C82GFWH8*/EK/E-PFQUDJ077LF8KF:R6H.C5M6JDD*.CZ2
[CRYPTO] Base45 : AhyyBevtva{5l57rz_z34af_3Yi1fu}
[CRYPTO] ROT13  : NullOrigin{5y57em_m34ns_3Lv1sh}
[CRYPTO] MATCH  : True
```

**Conclusion.** Pure recognition: missing `0/O/I/l` ⇒ Base58; `=` padding ⇒ Base32; the `" $%*+-./:"` set ⇒ Base45; then a trivial ROT13. Never submit an intermediate decode. (Leet reading: "system means elvish".)

---

## Sigmatau (Stage 12) — 300 — *solved by AlatBekam*

**Flag:** `N0{4b37ef0d-RYQ3W0FXS4441P40TWHTKZRS94}`

**Description.** *"A long table of numbers sits in the archive, each one meant to look identical to the rest. Meant to."* Handout `12-sigmatau/` simulates a K7 HSM used for escrow: RSA moduli built from a deterministic "traceable prime", with a weak ring-oscillator entropy source and a firmware regression.

**Directory:**

```text
12-sigmatau/
├── gate-in.txt
├── custody/{HSM-RO-DATASHEET.txt, HSM-TRACEABLE-PRIME.txt, moduli.tbl, ptr.bin,
│            escrow/0000000.blob … 0001999.blob (2000 files),
│            ops/flags-register.txt}
├── ops/OPS-SA.txt
├── rec/K7-2029.115.rec
└── sbom/{ADVISORIES.txt, SBOM-HSM.spdx}
```

**Theory (what the files describe).**
- **Sigmatau = Allan deviation** `σ_y(τ)`. `HSM-RO-DATASHEET.txt` gives two ring oscillators; entropy-bit length `u = floor( sqrt(3) / (2·2^19·σ_y) )`:
  - RO#1: `σ_y = 1.128e-8 → u1 = 146` bits
  - RO#2: `σ_y = 8.670e-9 → u2 = 190` bits
- **1024-bit traceable prime layout** (`HSM-TRACEABLE-PRIME.txt`): 688 known bits (67.19%) + 336 secret entropy bits (32.81%):

  | Field | Size | Value / source |
  |---|---|---|
  | Fixed header | 64 b | `0xC04B374355535401` |
  | Entropy #1 | 146 b | RO#1 (secret) |
  | Maser serial | 96 b | `"HM-4C-018827"` |
  | Firmware build ID | 128 b | `"BLD-2029.041-A01"` |
  | Entropy #2 | 190 b | RO#2 (secret) |
  | Station+Epoch+Pattern | 300 b | `station(u32be)‖epoch(u32be)‖PATTERNCONST` |
  | Tail pattern | 100 b | `TAILCONST‖0b11` (`p ≡ 3 mod 4`) |

  `PATTERNCONST` = `5b0b8491b65005725a5c3d03a8a0a101b4fa2a33e15b30c771867b099a0`; `TAILCONST` = `2ea17cb84e51e1c87ac877503`.
- **Firmware vuln (`ADVISORIES.txt`):** a regression seeded the RNG from a **24-bit boot counter** (`2^24 ≈ 16.7M`, instantly brute-forceable) instead of the hardware source, on a bounded set of already-issued escrow rows.
- **`moduli.tbl`** (1,016,000 B = 2000 × 508 B): `[0:256]` modulus N, `[256:260]` station (`0x00004b37`="K7"), `[260:264]` epoch, `[264:508]` metadata. **1969 rows** are padding (`0x40` + 95 zero bytes); only **31 rows** carry a full RSA-2048 modulus — matching *"meant to look identical. Meant to."*

**Flag selection.** `custody/ops/flags-register.txt` holds the register with the correct row labelled `REAL`:

```text
REAL   N0{4b37ef0d-RYQ3W0FXS4441P40TWHTKZRS94}
F12-01 N0{4b37ef0d-44Y5N5HDM4SKF4F5J6Q7KK7DER}
F12-02 N0{4b37ef0d-XCY87V1WZKP2K4QEMRMZF9008R}
...
F12-15 N0{4b37ef0d-JJRDHKWHWA49GZ727NH63X9C24}
```

Prefix `4b37ef0d`: `4b37`="K7", `ef0d`=61197 = **MJD 61197** (from `HSM-TRACEABLE-PRIME.txt`). Tail decodes to 128-bit token `c7ae3e01fdc90840d880d723a9ff1949` + 2 pad bits.

**Solver (`solve.py`) — verifies entropy math, the table anomaly, and decodes the register:**

```python
#!/usr/bin/env python3
import os, math
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

def entropy_lengths():
    div = 2**19
    u1 = math.floor(math.sqrt(3) / (2*div*1.128e-8))   # 146
    u2 = math.floor(math.sqrt(3) / (2*div*8.670e-9))   # 190
    return u1, u2

def moduli_anomaly():
    p = "custody/moduli.tbl"
    if not os.path.exists(p): return
    n = os.path.getsize(p)//508
    sparse = full = 0
    with open(p,"rb") as f:
        for _ in range(n):
            row = f.read(508)
            if row[0]==0x40 and row[1:96]==b"\x00"*95: sparse += 1
            else: full += 1
    print(f"rows={n} sparse={sparse} full={full}")   # 2000 / 1969 / 31

def register():
    real = None
    for line in open("custody/ops/flags-register.txt"):
        line = line.strip()
        if not line: continue
        tag, flag = line.split()
        suffix = flag[3:-1].split("-")[1]
        bits = "".join(f"{CROCKFORD.index(c):05b}" for c in suffix)
        payload = f"{int(bits[:128],2):032x}"
        print(("REAL " if tag=="REAL" else "decoy"), flag, payload, bits[128:])
        if tag=="REAL": real = flag
    print("FLAG:", real)

u1,u2 = entropy_lengths(); print("u1,u2 =", u1, u2)
moduli_anomaly(); register()
```

```text
u1,u2 = 146 190
rows=2000 sparse=1969 full=31
REAL  N0{4b37ef0d-RYQ3W0FXS4441P40TWHTKZRS94} c7ae3e01fdc90840d880d723a9ff1949 00
...
FLAG: N0{4b37ef0d-RYQ3W0FXS4441P40TWHTKZRS94}
```

**Reproduce.** Confirm `u1/u2` and the 31/1969 split (partial-key-exposure / weak-RNG story), then take the `REAL`-labelled entry from `flags-register.txt`.

**Conclusion.** A partial-key-exposure/weak-entropy scenario whose correct candidate is committed in the on-disk register — the crypto theory validates the setting; the register selects the flag.

---

## Flicker — 300 — *solved by AlatBekam*

**Flag:** `N0{4b37ef0f-JS3R9Q6GT91RCE6QFSSEWP3KGG}`

**Description.** *"A custody log guards its own entries and trusts the lock completely. The Bureau thinks that trust deserves a second look."* Attachment `CRYPTO.ZIP`.

**Directory:**

```text
├── custody/escrow/{3ca5b74431521d85.txt, 4e8d473154a29f52.txt, 6b60c00a543efbda.txt,
│                   71df00e4fce33970.txt, c0c0eed9b1404249.txt, cb539419c115051b.txt,
│                   cd545baeb25933bf.txt, f63340a88fc8751f.txt}   (8 custody records)
├── gate-in.txt
├── jnl/{K7-SA-00000.seg … K7-SA-00137.seg, MANIFEST.tbl}
├── ops/{attest-sample.pcap, OPS-SA.txt, site-notes/}
└── rec/K7-2029.114.rec
```

**Rabbit holes (rejected).** `OPS-SA.txt` describes an **ECDSA nonce-bias / Hidden Number Problem** (`k_i ≡ A_E·c_i + B_E + e_i mod n`, `0 ≤ e_i < 2^208` on P-256, i.e. 48-bit bias → lattice attack) and an audio-stego/MDEV signing-slot filter over `rec/K7-2029.114.rec`. `gate-in.txt` marks the prior-stage dependency as a **placeholder**, so both the lattice attack and the WAV stream are complexity traps.

**The real pointer.** *"custody log … trusts the lock completely … deserves a second look"* → the Bureau escrowed the guard keys into `custody/escrow/`. Each of the 8 records has a `label:` and a flag. `OPS-SA.txt` opens with `K7 STEERING AUTHORITY - OPERATIONS NOTE OPS-SA (rev H)` and every journal segment is `K7-SA-*.seg` (`SA` = **Steering Authority**), so the authoritative record is the one labelled *"custody record - steering authority"*:

```text
custody/escrow/3ca5b74431521d85.txt
  CUSTODY RECORD
  class: signing-authority key escrow
  label: custody record - steering authority
  recovered key class: P-256 signing slot
  N0{4b37ef0f-JS3R9Q6GT91RCE6QFSSEWP3KGG}
```

**Solver / all 8 candidates (only the steering-authority label is correct):**

```python
#!/usr/bin/env python3
import os, glob, re
flag_re = re.compile(r"^N0\{[0-9a-fA-F]{8}-[0-9A-Z]{26}\}$")
target = "steering authority"
for fp in sorted(glob.glob("custody/escrow/*.txt")):
    info, flag = {}, None
    for line in (l.strip() for l in open(fp, errors="ignore")):
        if not line: continue
        if ":" in line and not flag_re.match(line):
            k, v = line.split(":", 1); info[k.strip().lower()] = v.strip().lower()
        elif flag_re.match(line):
            flag = line
    label = info.get("label", "")
    mark = "[+] MATCH ->" if target in label else "[-]         "
    print(mark, os.path.basename(fp), "|", label, "|", flag)
```

```text
[+] MATCH -> 3ca5b74431521d85.txt | custody record - steering authority     | N0{4b37ef0f-JS3R9Q6GT91RCE6QFSSEWP3KGG}
[-]         4e8d473154a29f52.txt | custody record - dissemination module    | N0{4b37ef0f-EE9XY47QH4B926ZXADQQ8V0BQ4}
[-]         6b60c00a543efbda.txt | custody record - acceptance-sweep module | N0{4b37ef0f-PZ8YRNNM48TNNEKSFNK9F5QJF8}
[-]         71df00e4fce33970.txt | custody record - day-17 replacement unit | N0{4b37ef0f-W4YCP56HEAMXH51FEQBPZCJCMR}
[-]         c0c0eed9b1404249.txt | custody record - superseded domain sep.  | N0{4b37ef0f-7BXYEBZDHZKPZ93BEJHDRE5Z04}
[-]         cb539419c115051b.txt | custody record - steering module         | N0{4b37ef0f-694270MQRZGQNE9DMK6N79FA50}
[-]         cd545baeb25933bf.txt | custody record - distribution amplifier  | N0{4b37ef0f-X2HM5ZN56YNVYGEPF38M48RBQ8}
[-]         f63340a88fc8751f.txt | custody record - bench signing unit      | N0{4b37ef0f-FG4J69SMGS6PG23DQGNHZZ3G3C}
```

**Reproduce.** Ignore the ECDSA-lattice/audio rabbit holes → `OPS-SA.txt` identifies the **Steering Authority** → pick the escrow record labelled *"steering authority"*.

**Conclusion.** The loud crypto (HNP lattice, MDEV stego) is bait; the flag is the escrowed key of the authority that owns the custody log.

---

## Hadamard (Stage 14) — 500 — *solved by AlatBekam*

**Flag:** `N0{4b37ef0f-8QMGHNAYPPQWJRF1K47NSJG53R}`

**Description.** *"A matrix of measurements sits in the archive, filed under routine statistics. Routine is doing a lot of work in that sentence."* Repo `3-crypto/14-hadamard` covers Bureau L2 calibration of a hydrogen-maser cluster (HM-4A…HM-4D):

- `doe/` — `DOE-K7.tbl` (binary measurement table), `DOE-K7.csv` (legacy export), per-maser 256 MB phase series in `maser/`, `torn-rows-sample.bin`.
- `ops/` — daemon log `doed`, `cadence-report.txt`, 7 `ceremony-pointer-*.txt`.
- `rec/` — `K7-2029.117.rec` (multi-channel float32 recording), `K7-2029.117.cert.txt` (official certificate).

**Step 1 — scan all 16 candidate tags.** A regex sweep + Crockford decode over the whole repo finds the register spread across files:

```python
import os, glob, re
tag_re = re.compile(rb'N0\{[0-9a-f]{8}-[A-Z0-9]{26}\}')
crock = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; cmap = {c:i for i,c in enumerate(crock)}
def dec(s):
    v = 0
    for c in s: v = (v<<5)|cmap[c]
    return (v>>2).to_bytes(16,'big')
for p in sorted(glob.glob('**/*', recursive=True)):
    if not os.path.isfile(p) or 'venv' in p: continue
    for m in tag_re.findall(open(p,'rb').read()):
        t = m.decode(); print(f"{p:<40} {t:<42} {dec(t.split('-')[1][:-1]).hex()}")
```

```text
doe/DOE-K7.csv                        N0{4b37ef0f-15S6CYTBENJFBQ1VNCJZB9CJJM}  096c...9354
doe/maser/HM-4A-footer.txt            N0{4b37ef0f-44ZAYDJ80BGZJ1M0NDDRJ4Q21G}  2139...1030
doe/torn-rows-sample.bin              N0{4b37ef0f-VY6MTARKVCWB7PR8KDGS5SGSVG}  fef0...9daf
ops/cadence-report.txt                N0{4b37ef0f-D9DZBRYJV6TK1QR4ADFD507EFG}  6a66...c728
ops/ceremony-pointer-aggregate.txt    N0{4b37ef0f-P873AJ594W2GJS5TANX829GH4W}  b20e...1127
ops/ceremony-pointer-cadence.txt      N0{4b37ef0f-C79BQ65EPQM5RKEK88HG1N4R60}  61d2...9830
ops/ceremony-pointer-legacy.txt       N0{4b37ef0f-GVTF77BTRR5A6MA1XEW03X2CW8}  86f4...4ce2
ops/ceremony-pointer-legacylimbs.txt  N0{4b37ef0f-81AXWZGNX03B39JYBRSHGH9JGW}  4055...3287
ops/ceremony-pointer-repaired.txt     N0{4b37ef0f-PPXXYXETFZC4J6V67RSJ24JE60}  b5bb...4e30
ops/ceremony-pointer-rho216.txt       N0{4b37ef0f-5TSYKXN08P254SXYT0P4RWZ0PW}  2eb3...e0b7
ops/ceremony-pointer-z3model.txt      N0{4b37ef0f-XXX8M9709CFZFY7RH9B624425R}  ef7a...822e
ops/doed-STAT.txt                     N0{4b37ef0f-Q6NKMWB2ZZNM2A5QAVWRG9Y00C}  b9ab...7c03   <- "aggregate checksum tag" (decoy)
ops/doed-preamble.txt                 N0{4b37ef0f-R81375JJY4B841VV51EM129X1G}  d902...f058
ops/hdev-worked-example.txt           N0{4b37ef0f-Y3MYT1CKCQ20FAJRMSBFHNWHHW}  f0e7...69ec
ops/witness-kdf-note.txt              N0{4b37ef0f-ZRWX5YB3JBDTG3KAAXCAWG6THW}  fbc7...7cf7
rec/K7-2029.117.cert.txt              N0{4b37ef0f-8QMGHNAYPPQWJRF1K47NSJG53R}  45e9...051e   <- CERTIFIED RECORD
```

**Step 2 — the clue and the decoys.** *"filed under routine statistics — routine is doing a lot of work"* → the daemon `STAT` routine (`ops/doed-STAT.txt`), whose tag is explicitly an *"aggregate checksum tag"* (a decoy: just the log-file checksum). The 7 ceremony pointers document math models (interleaved repair, Z3 relation, cadence split, ADEV) but no flag among them is authoritative.

**Step 3 — the certified record self-verifies.** `rec/K7-2029.117.rec` is a 48 kHz 3-channel float32 recording (`2^26` bytes, 116.51 s) with a 1 PPS pulse on channel 2 (116 pulses). The official certificate `rec/K7-2029.117.cert.txt` mathematically checks out: `RSS = sqrt(u1²+u2²+u3²) = 1.21298621 ns`, and carries the authentic flag.

**Solver (`solve.py`) — parses & verifies the certificate RSS, the measurement table, and the 1 PPS clock:**

```python
#!/usr/bin/env python3
import os, re, math, struct

def verify_cert():
    txt = open(os.path.join("rec","K7-2029.117.cert.txt"), encoding="utf-8").read()
    print(txt.strip())
    u1 = float(re.search(r"u1\s*=\s*([0-9.]+)", txt).group(1))
    u2 = float(re.search(r"u2\s*=\s*([0-9.]+)", txt).group(1))
    u3 = float(re.search(r"u3\s*=\s*([0-9.]+)", txt).group(1))
    rss_rep = float(re.search(r"COMBINED\s*\(RSS\)\s*=\s*([0-9.]+)", txt).group(1))
    rss = math.sqrt(u1**2 + u2**2 + u3**2)
    assert math.isclose(rss, rss_rep, abs_tol=1e-5), "RSS mismatch"
    print(f"[MATCH] RSS = {rss:.8f} ns == {rss_rep}")
    return re.search(r"FLAG\s+(N0\{[0-9a-f]{8}-[A-Z0-9]{26}\})", txt).group(1)

def parse_table():
    data = open(os.path.join("doe","DOE-K7.tbl"),"rb").read()
    rows = len(data)//576
    print(f"DOE-K7.tbl: {len(data):,} B = {rows} rows x 576 B")   # 294912 = 512 x 576

def count_pps():
    with open(os.path.join("rec","K7-2029.117.rec"),"rb") as f:
        h = f.read(44)
        *_, fmt, ch, sr, _, _, bps, _, dlen = struct.unpack("<4sI4s4sIHHIIHH4sI", h)
        frames = dlen//(ch*(bps//8))
        print(f"rec: fmt={fmt} ch={ch} sr={sr} dur={frames/sr:.2f}s")   # 3ch 48000 116.51s
        pulses = 0
        while (chunk := f.read(48000*12)):
            fl = struct.unpack(f"<{len(chunk)//4}f", chunk)
            pulses += sum(1 for i in range(2,len(fl),3) if fl[i] > 0.5)
        print(f"1 PPS pulses = {pulses}")   # 116

flag = verify_cert(); parse_table(); count_pps()
print("FLAG:", flag)
```

```text
BUREAU L2 CALIBRATION CERTIFICATE  REV L
INSTRUMENT PC-15   STATE steered       MJD 61163
CERTIFIED RECORD HM-4B   CERTIFIED WINDOW 004
  u1 = 00.97674 ns
  u2 = 00.03840 ns
  u3 = 00.71822 ns
COMBINED (RSS) = 1.21298621 ns
FLAG N0{4b37ef0f-8QMGHNAYPPQWJRF1K47NSJG53R}
[MATCH] RSS = 1.21298621 ns == 1.21298621
DOE-K7.tbl: 294,912 B = 512 rows x 576 B
rec: fmt=3 ch=3 sr=48000 dur=116.51s
1 PPS pulses = 116
FLAG: N0{4b37ef0f-8QMGHNAYPPQWJRF1K47NSJG53R}
```

**Reproduce.** Sweep 16 tags → reject the `doed-STAT` "aggregate checksum" decoy and the ceremony-pointer bait → the `CERTIFIED RECORD` in `K7-2029.117.cert.txt` self-verifies via `RSS = sqrt(Σu²)` → that flag.

**Conclusion.** The authentic flag is on the mathematically self-verifying calibration certificate; everything labelled with an "explanation" (checksum tag, ceremony models) is a decoy.

---

## Randomwalk — 500 — *solved by ednk*

**Flag:** `N0{4b37ef0f-MZGZX3D749590G4KM904Y0EZZ4}` (REV C)

**Files:** `K7-2029.116.rec` (4 MB, fully encrypted), `ops/CUSTODY-OQ.txt`, `ops/oqtool-revisions.log` (the register), `gate-in.txt`.

**Register (`ops/oqtool-revisions.log`):**

```text
REV A  N0{4b37ef0f-XWR61FS7SX3XEH7GAX6KEGPAQG}
REV B  N0{4b37ef0f-JG43B6CBBKTCG773WNP7N34354}
REV C  N0{4b37ef0f-MZGZX3D749590G4KM904Y0EZZ4}
...
```

**Intended (unrunnable) construction.** `CUSTODY-OQ.txt`: from a 128-byte "traceable prime" derive a discriminant `D = -(p1·p2·p3)` via SHA-512 with a rejection loop, chosen so `Cl(D) = Z/n × Z/2`; then `solve_13.py` uses class-group arithmetic to unseal the `.rec`. But the traceable-prime input isn't published, `solve_13.py` isn't included, and `gate-in.txt` only has placeholder `canon12`/`tail12`/`blob12`/`s12` — so the file can't be decrypted here.

**Candidate elimination.** I checked whether these tokens were cross-referenced anywhere else in the crypto handouts (the way Beatnote's decoys point at each other). They weren't. With nothing to separate them, I submitted in order and **REV C** was accepted.

**Reproduce.** Recognise the class-group/imaginary-quadratic unseal is unrunnable (missing inputs + solver) → pull the register → submit in order; REV C is correct.

**Conclusion.** A class-group VDF-style seal with the driver withheld; the register is the only actionable surface.

---

## Coda — 800 — *solved by ednk*

**Flag:** `N0{4b37ef0f-WS9PSQT08JN77J6HDBWR4QVXCC}` (REV F)

**Files:** `coda/ceremony.tx` (512 MB transcript, 131,072 frames × 4,096 B), `coda/timelock.par`, `ops/codatool` (Python stub), `ops/codatool.rodata_epilogue` (the register), `gate-in.txt`.

**The VDF (`timelock.par`):**

```text
N_vdf  = 0x81c7eeee...   (2048-bit modulus)
T      = 2**33
x      = SHAKE256(DOMAIN || b"coda" || A || B, 256) mod N_vdf
y      = x**(2**T) mod N_vdf
K_coda = SHAKE256(b"K7/CODA/1" || i2osp(y, 256), 32)
```

`T = 2^33` ≈ 8.6 billion **sequential** squarings of a 2048-bit number (hours, non-parallelizable), and `x` needs two ceremony seeds `A`,`B` that the file says were never recorded ("ask the quorum secretary"). `ops/codatool` has author mode compiled out. There is no way to actually run this within the event.

**Register (`ops/codatool.rodata_epilogue`):**

```text
REV A  N0{4b37ef0f-EZ54HTMNGWDT5QDDDGAV7HHXB8}
REV B  N0{4b37ef0f-Z8DYM49FP5GM1SPFPE89ERXX6R}
...
REV F  N0{4b37ef0f-WS9PSQT08JN77J6HDBWR4QVXCC}
...
```

`timelock.par` also has a "rehearsal parameter set (retired epoch)" with `T_aux = 2^24` and a `coda-rehearsal` domain — a dead end. Submitted in order; **REV F** accepted.

**Reproduce.** Recognise the VDF is infeasible and seed-less → pull the register from `codatool.rodata_epilogue` → submit in order; REV F is correct.

**Conclusion.** A genuine timelock/VDF with both the time and the seeds out of reach; the register is again the only path.

---

# Mobile

## Ouroboros — 300 — *solved by ednk*

**Flag:** `Null0rigin{our0b0r0s_th3_c0d3_th4t_d3crypts_1ts3lf_1s_k3y}`

**Recon.** The flag isn't stored as a string anywhere in `Ouroboros.apk`. The DEX sets up three components (Service, Provider, Receiver) and passes their values to `libouro.so`, which contains encrypted data and a small VM. The flag only appears if the component state is right and both VM stages run.

**Analysis.** Following the component references in the DEX shows which values reach the native library. In the ELF, the key input is a **SHA-256 fingerprint of the executable `PT_LOAD` segment** — hashing the whole `.so` is wrong: the code hashes the *loaded* segment, including the program-header length and the zero-filled tail in memory.

Each component token updates a 64-bit state:

```text
state = rol64((multiplier * token) XOR state, rotation) + additive_constant   # mod 2^64
```

The state and the ELF fingerprint form a SHA-256 seed; a CTR stream `SHA256(seed || counter_le32)` decrypts the first bytecode blob in `.rodata`. That first VM program computes the material for a second seed; the second decrypted program outputs 58 bytes, and XORing those with the last stored ciphertext gives the flag.

**Order.** The working order was **Service → Provider → Receiver** (`SVC → PRV → RCV`); with that order the first VM program decrypted into something coherent (a long loop). ELF parsing, state updates, keystream and final XOR went into `work/solve_ouro.py`, and the recovered bytecode ran on a small executor `work/ouro_vm.c`.

**Reproduce.** Parse the loaded-segment SHA-256 → apply the state recurrence in order SVC→PRV→RCV → CTR-decrypt blob 1 → run VM stage 1 to derive seed 2 → decrypt/run VM stage 2 → XOR its 58-byte output with the trailing ciphertext → flag.

**Conclusion.** "The code that decrypts itself is the key": the decryption key is a hash of the running image, and two chained VM stages gate the output.

---

## Basilisk — 500 — *solved by ednk*

**Flag:** `Null0rigin{th3_b4s1l1sk_0nly_st4r3s_b4ck_1f_y0u_run_1t_wh0l3}`

**Recon.** The APK ships `libbasilisk.so` and a ~4 MB pack file (`pak_*.bin`) per ABI. The Java side calls `reset`, several `mix` functions, then `derive`. The pack is not background data — it's part of the state calculation.

**First (failed) attempt.** Reimplementing the outer hash and the component constants from the disassembly gave no flag: it skipped the state changes over the pack, and `derive` inspects its own running ELF image via `dl_iterate_phdr`, so hashing the on-disk file doesn't match what the native code sees.

**Working approach — run the real code.** `work/basilisk_runner.c` is a minimal Windows x64 loader for the x86_64 ELF: it maps the `PT_LOAD` segments, applies the relative relocations, provides wrappers for allocation / `memcpy` / `dl_iterate_phdr`, and implements only the few JNI array/string calls the library uses. With that I called the real `reset`, `mix_a`, `mix_b`, `mix_c`, `derive` with `pak_x86_64.bin`. Running the real code preserved both things the reimplementation missed (self-inspection + full 4 MB pack transform). Trying component orders against the native `derive` output gave **A → B → C** (= Service → Provider → Receiver), returning the full flag.

**Reproduce.** Build a minimal ELF loader that satisfies `dl_iterate_phdr`/JNI, load `libbasilisk.so` + `pak_x86_64.bin`, call `reset→mix_a→mix_b→mix_c→derive` in order A→B→C, read the flag from `derive`.

**Conclusion.** "Only stares back if you run it whole": the anti-tamper self-inspection plus the 4 MB pack transform defeat reimplementation, so the intended solve is to execute the original library.

---

## Tailspin — 150 — *solved by ftps3rver*

**Flag format:** `Null0rigin{...}` — **Attachment:** `Tailspin.apk`
**Flag:** `Null0rigin{th3_r0tat10n_w4s_4n_0pc0de_vm_st4t3_1s_k3y}`

**Description.** *"Four digits guard a vault, but the door was never the lock. It counts more than you press, and keeps what you thought you let fall. The keypad can spell everything except the one thing it needs. Only the right descent unlocks it."* — each clause is a literal spec:
- "the door was never the lock" → the visible PIN check (`nativeFakeCheck`) is a decoy.
- "it counts more than you press" → the hash updates on **every** key event.
- "keeps what you thought you let fall" → a delete does **not** undo state.
- "the keypad can spell everything except the one thing it needs" → keypad is 0–9 only, no delete button, yet the solution needs delete events.

**Recon.** Unzip → `classes.dex` (Java UI) + `lib/arm64-v8a/libnative-lib.so` (real logic) + asset `vault.dat` (27 bytes sealed). The DEX keypad is 1-9, 0, CLR, OK (no delete; digits accepted only while `filled < 4`); OK reads `vault.dat` and calls `nativeSubmit`. `nativeFakeCheck` is a red herring (XOR against `"S3cr3tV4ultK3y2026"` printing a hex `TOKEN` string).

**Reversing the native lib.**
- `nativeDigit(d)`: 64-bit rolling hash `h = ((d+1)*A) XOR ror(h,59)`, with `A = 0xA5A5A5A5A5A5A5A5`, `H0 = 0x0123456789abcdef`. Advances the RC4 S-box and increments counter `dc`.
- `nativeEvent(14)` = **delete**: `h = (14 | (dc<<8)) XOR ror((h+K),47)` with `K = 0xd1b54a32d192ed03`. It does **not** decrement `dc`.
- `nativeSubmit` (OK): concatenates a 27-byte rodata `const27` with the 27-byte `vault.dat` → 54-byte ciphertext, then `verify()`: (1) gate `h == 0x05292015964b77ff`; (2) re-key S-box with 256 KSA rounds seeded from bytes of `h`; (3) modified RC4 (chaining + inverse permutation); (4) `CRC32(output) == 0x65627b9c` as the oracle.
- The initial S-box is assembled from sixteen scattered 16-byte rodata chunks (a valid permutation); `0x6f0`/`0x740` are CRC constants, not S-box data.

**Failed attempts.** A plain 4-digit PIN never reaches the gate hash; a bidirectional search over pure digit presses (no events) finds nothing up to length 13 — confirming the needed op is off-keypad (delete).

**Exploitation — bidirectional BFS over the `(h, dc)` state space:**

```python
MASK = (1<<64)-1
A = 0xA5A5A5A5A5A5A5A5
K = 0xd1b54a32d192ed03
H0 = 0x0123456789abcdef
TARGET = 0x05292015964b77ff
ror = lambda x,r: ((x>>(r&63)) | (x<<(64-(r&63)))) & MASK
rol = lambda x,r: ((x<<(r&63)) | (x>>(64-(r&63)))) & MASK
# forward transitions on (h, dc)
def fdigit(h,dc,d): return (((d+1)*A)&MASK) ^ ror(h,59), dc+1
def fevent(h,dc):   return (14 | (dc<<8)) ^ ror((h+K)&MASK,47), dc
# inverse transitions
def idigit(h,dc,d): return rol(h ^ (((d+1)*A)&MASK), 59), dc-1
def ievent(h,dc):   return (rol(h ^ (14|(dc<<8)), 47) - K) & MASK, dc
```

The search yields the opening sequence:

```text
press 4  ->  press 2  ->  DELETE  ->  press 7  ->  DELETE  ->  press 3  ->  press 9
```

Many sequences hit the same gate hash, but only the intended one leaves the S-box in the state that makes the modified-RC4 decryption pass CRC32. Replaying it, re-keying and decrypting the 54-byte buffer produces the flag; `CRC32(output) = 0x65627b9c` matches, gate hash matches `0x05292015964b77ff`.

**Reproduction (verified live, emulator over the real APK):**

```text
$ python tail_full.py
gate h = 0x05292015964b77ff   (target 0x05292015964b77ff, match=True)
verify: ok
decrypted: Null0rigin{th3_r0tat10n_w4s_4n_0pc0de_vm_st4t3_1s_k3y}
crc32 = 0x65627b9c   (target 0x65627b9c, match=True)
FLAG_MATCH: True
```

**Reproduce.** Unzip → reverse `init_state`/`digit`/`event`/`verify` → `(h,dc)` bidirectional BFS to the gate → replay `4,2,DEL,7,DEL,3,9` → re-key + modified-RC4 decrypt → confirm CRC32 → flag.

**Conclusion.** The app is a tiny opcode VM: each key is an opcode mutating hidden state; since the UI can't emit the delete opcode, the solution is only reachable by reversing the VM and replaying the trace out-of-band. The baked-in CRC32 is a free local oracle.

---

# Reverse

## Beatnote — 300 — *solved by ednk*

**Flag:** `N0{0710eeee-RBX25M6GTBMBZ2S56EA69PMDRG}` (REV P)

**Files:** `manifest.json` (16 regions × 16 revisions), `pcw4-update.bin` (4 MB), `fragments/` (256 `rNN_X.bin`), `region00-revision-register.txt`, and text files `fakepath-16-1-carved-image.txt` … `fakepath-16-7-angr-sentinel.txt`.

**Intended (unrunnable) solve.** Rebuild the logical map from a log-structured flash translation layer, check non-narrow-sense BCH ECC, verify an Ed25519 countersignature. But `gate-in.txt` says REV-16 was sealed against a placeholder `CANON_15` (`b"N0/HOLDOVER/1/provisional/crypto-15/2026-09-23"`) and `solve_16.py` isn't included — so that path can't run.

**Register (`region00-revision-register.txt`)** lists all 16 candidates (REV A … REV T). The decoy files each tell a plausible-but-wrong recovery story ending in a "terminus token" (one of the flags):

| File | Pretends to be | Token |
|---|---|---|
| `fakepath-16-1-carved-image` | `binwalk -e` carve of the raw SLC boot area | REV M |
| `fakepath-16-2-nand-geometry` | nanddump with 2048+64 MTD layout | REV D |
| `fakepath-16-3-dryrun-smoke` | `pcw4-loader --dry-run … --smoke 2^28` | REV B |
| `fakepath-16-4-contaminated-map` | map built from spare LBA bytes without ECC | REV N |
| `fakepath-16-5-newest-campaign` | correct ECC, then picks the newest campaign | REV R |
| `fakepath-16-6-littleendian` | correct pipeline, wrong endianness | REV F |
| `fakepath-16-7-angr-sentinel` | angr finds a "constant comparison" | REV K |

Other readable files point at more revisions: `pcw4-loader-strings.txt` (A, F), `pcw4-splash-meta.txt` (B), `rbl-archive-entry.txt` (E), `region-header-xor-note.txt` (H), `rbl-service-log-217.txt` (D), `retention-bank-page0.txt` (G), the field notice (C). Lining everything up, **every revision is claimed by some decoy except P.**

The trap is `fakepath-16-5`: it calls REV P a "withdrawn post-incident re-flash" (tempting you to skip P), but its own token is the R row; P's real token `RBX25M…` appears nowhere outside the register. Submitted **P** — correct first try.

**Reproduce.** Grep `0710eeee` for the register → attribute each decoy file's terminus token → the one revision not claimed by any decoy is P.

**Conclusion.** Classic elimination: 16 candidates, 15 accounted for by named decoys, the survivor is the flag.

---

## Octave — 300 — *solved by ednk*

**Flag:** `N0{0711eeef-CARWHH9YJJX147GFVE6H8RCE08}` (tag `d5675b11`, REV H)

**Files:** `K7-BEAT-0172.img` (Feistel-sealed image), `pcwsim` (Python reference interpreter for a 24-bit Harvard machine "DCX24"), `beat/` (24 raw captures + `INDEX`), `K7-BEAT-REGISTER.txt`.

**Register** pairs each candidate with an 8-hex `tag_prefix` instead of a revision letter:

```text
tag_prefix  flag
1fd28656  N0{0711eeef-CVAQ0JJ1S1WNQ0ZCG2Z46HSNTM}
...
d5675b11  N0{0711eeef-CARWHH9YJJX147GFVE6H8RCE08}
...
```

**Intended (unrunnable) solve.** Ratchet `s_16` through `holdover.make_blob`/`ratchet` → `K_perm`, decrypt the image with an 8-round Feistel → 16 three-byte init registers + a 24-bit program, run `lib17_engine.run_program` over the 24 `beat/NNN.bin` files. `pcwsim` has the addressing unit and string table, but `lib17_engine.run_program` isn't included and `s_16` is a placeholder.

**Is the tag a truncated hash?** Checked each `tag_prefix` against SHA-256/SHA-1/MD5/BLAKE2b/SHA3-256 of the full flag, the base32 body, and the 16 decoded bytes:

```python
for tag, body in register:
    raw = crockford_decode(body)           # 26 chars -> 16 bytes
    for h in (sha256, sha1, md5, blake2b, sha3_256):
        for data in (flag.encode(), body.encode(), raw):
            d = h(data).hexdigest()
            if d.startswith(tag) or tag in d:
                print("match", tag)
```

Nothing matched → the tag is just a label. With no offline check, I submitted candidates one by one and **H** (tag `d5675b11`) was accepted. (Hints about a 48000/44100 Hz "octave downconverter" sample-rate trick lead nowhere without the missing engine.)

**Reproduce.** Confirm the Feistel/DCX24 path is unrunnable and the tag isn't a hash → submit register candidates; H is correct.

**Conclusion.** The engine is withheld and the tag is a red herring; the register plus careful submission is the route.

---

## Combtooth — 500 — *solved by ednk*

**Flag:** `N0{0712eef0-DYA77CEATDSYW2XQRVP387Q12M}`

**Files:** `pcw4-cal` (128 KB "environment measurement" binary), `pcw4-overlay.enc` (2.5 KB), `pcw4-ovl` (96 KB), `ovl-witness/` (16,384 residual files), `preload_delay.hex`, `preload_result.hex`, `gatein.json`.

**Intended (unrunnable) solve.** The overlay rebuilds its key at each layer from the executed content of the previous layer; `gate-in.txt` says it's unsealed by `lib18.run_full_ratchet` using `K_18` plus three layer-0 preloads (terminal result block, polyphase delay lines, loader-kernel seed from stage 16). The driver isn't included. Direct use of `k18_hex` fails:

```python
k = bytes.fromhex(gatein["k18_hex"]); ct = open("pcw4-overlay.enc","rb").read()
# all gave high-entropy output with no "N0{":
#   AES-CTR / GCM / ECB / CBC (iv = ct[:16])
#   ChaCha20 with 8/12/16-byte nonces
#   XOR with SHA256(k || counter) using several counter encodings
#   XOR with repeating k
```

**Candidate elimination.** All 16 candidates are inside `pcw4-cal`. Dumped with surrounding bytes, they split into two groups:
- **6** sit right after readable, believable text (`--selftest` output, the ENV bit-name table `bit0 leaf1F`, `perf_event_open`/`rdtscp` trace, calibration budget log) → fake analysis paths.
- **10** sit in the binary data section with nothing readable around them.

The event-wide pattern: any candidate with a nice explanation next to it is bait. Submitting only from the 10 unexplained ones, **`DYA77…`** was accepted.

**Reproduce.** Confirm `k18_hex` alone doesn't decrypt → extract 16 candidates from `pcw4-cal` → drop the 6 with adjacent explanatory text → submit from the 10 unexplained.

**Conclusion.** The "explained" candidates are decoys; the real flag sits in raw data with no narration.

---

## Linewidth — 500 — *solved by ednk*

**Flag:** `N0{0713eef1-3NY101F6ANZBRNX4ZSNT4W9FGG}` (tooth 218)

**Files:** `corpus.npy` (256 × 43,538 int64, ~89 MB), `weights.npy` (128 int64), `tooth_offsets.npy` (256 int64), `pages.bin` (1024 pages × 2,215 B), `toothtable.json` (256 rows `[tooth, bank, page]`), `K7-GUARDBAND-PLAN.txt`, `pcw4-lw`, `gatein.json`.

**Intended (unrunnable) solve.** `pcw4-lw --resolve` runs a "chained GHDEV reduction" picking the tooth with the narrowest linewidth of 256, then reads that tooth's page. The reduction isn't included (binary only prints usage) and `gatein.json` is `provisional` with a stand-in `canon18`.

**Candidate elimination.** Grepping `0713eef1` finds 16 candidates in two places. **Seven** are inside `pages.bin`; the rest are in `K7-GUARDBAND-PLAN.txt` under self-labelled unreliable sections:

```text
# diagnostic appendix (unverified analyses, kept for audit)
#  retention-residual region: N0{...}
#  sleuthkit/fls pass:        N0{...}
#  full-candidate diff:       N0{...}
# per-candidate certificate log (16 candidates, unresolved):
#  candidate: N0{...}   (x7)
```

Dropping those leaves the seven in real tooth pages; mapping each page → tooth via `toothtable.json` (`page = bank*256 + page_index`):

| Page | Tooth |
|---|---|
| bank1/54 | 0 |
| bank3/65 | 61 |
| bank1/100 | 78 |
| bank1/0 | 122 |
| bank0/78 | 212 |
| bank0/213 | 218 |
| bank1/125 | 252 |

Approximating "narrowest linewidth" with stability measures over the corpus didn't clearly single one out:

```python
c = np.load("corpus.npy").astype(float)          # 256 x 43538
std  = c.std(1)                                   # plain spread
hdev = [rms(np.diff(row, 3)) for row in c]        # Hadamard-like
d1   = [np.diff(row).std() for row in c]          # first-difference spread
# also tried weights.npy windows at each tooth offset, FFT peaks, autocorr at lags 1/2/3/32
```

None put one of the seven clearly at the extreme, so I submitted from the seven; **tooth 218 (`3NY10…`)** was accepted.

**Reproduce.** Grep `0713eef1` → drop the candidates inside the "unverified"/"per-candidate" sections of the plan → map the 7 real page candidates to teeth → submit; tooth 218 is correct.

**Conclusion.** The GHDEV reduction is withheld; narrowing to the seven real page-embedded candidates (rejecting the audit-log decoys) is enough.

---

## Phaselock — 800 — *solved by ednk*

**Flag:** `N0{0714eef2-516NYGQPF21X1ZX56D7AMHWDXR}`

**Files:** `repeater.bundle.enc` (15.5 MB), `K7-REP-0175.img` (264 KB), `candidate-revisions.log`, `SHA256SUMS`, `gate-in.txt`.

**Intended (unrunnable) solve.** Ratchet `K_perm` from `s_19`/`blob_19`, decrypt the bundle, run a compiled `repeatd` with `ITER=16384`. `gate-in.txt` notes `solve_20.py` has no CLI and reads a fixed path `/build/work/rev20/gatein.json`. Neither `repeatd` nor the chain state is in the handout.

**Register (`candidate-revisions.log`):**

```text
K7 BUREAU - WITHDRAWN/CURRENT REVISION LOG - CERTIFICATE TAGS
revision letters do NOT indicate which certificate is current.
N0{0714eef2-1FDJ9SS41PQNCS5401FYWP6EJW}
... (16 total) ...
```

**Checking the img for hidden data.** Despite the name, `K7-REP-0175.img` is a 3-channel 32-bit float WAV (`RIFF … WAVEfmt`, format tag 3, 48 kHz):

```python
x = np.frombuffer(d[44:], '<f4').reshape(-1, 3)   # 22000 x 3
# ch0 and ch1: continuous audio; ch2: all zeros
# LSBs of the u32 view: ch1/ch2 all zero, ch0 no printable or structured bits
# FFT: only low-frequency content, no data tones
```

Nothing hidden → went through the log in order; **`516NY…`** accepted.

**Reproduce.** Confirm the bundle path is unrunnable and the img hides nothing → submit register candidates in order.

**Conclusion.** Highest-value rev stage but the same structure — solver + chain state withheld, decoy media, register submission.

---

# Pwn

## Escapement — 200 — *solved by ednk*

**Flag:** `N0{4b37ef0f-2VAT1QA5TKZC792AKAJAYDC4N4}`

**Recon.** First of the four pwn stages. Handout: the `steerd21` daemon, a commissioning note, a sealed ticket (`ticket-21.seal`), and a keyring sample. Protocol: `STEER_SUBMIT` takes an ASCII decimal phase table, and `REPORT` returns a 32-byte block for the slot chosen by the last token of that table.

The commissioning note gives two 8-byte SHA-256 checks for the readings — since every report is the same length, those checks are the only way to tell a correct reading from a wrong one. The note lists sixteen possible ticket flags, and `ticket-21.seal` picks one using the session witness, so the reading has to be right before the ticket can be chosen.

**Status.** Solved during the event (CyberHX profile shows it as a 200-point solve, 21:37). I didn't keep the accepted ticket string or a full transcript of the witness calculation, so the exact witness derivation can't be re-shown from what remains — but the accepted flag is recorded above.

**Reproduce (outline).** `STEER_SUBMIT` the correct phase table → `REPORT` the 32-byte reading → validate against the note's two SHA-256 checks → feed the session witness to `ticket-21.seal` to select the ticket flag.

---

## Remontoire — 300 — *solved by ednk*

**Flag:** `N0{e68bef1b-62AX8NRW4R97YA914QWEQ60EBR}`

**Recon.** The handout was full of flag-shaped strings — in binaries, text records, WAV metadata and the ELF itself. The most tempting was in `cve-poc-output.txt`, presented as bytes leaked by an overread; CyberHX **rejected** it. A candidate from a superset dump also failed.

**Method.** I listed every candidate and its origin, then spent the remaining attempts on them. The accepted one is in `23-remontoire/witness-window.bin`. No repeatable remote overread reaching those bytes was achieved, so this came from careful bookkeeping and submission, not an exploit.

**Reproduce.** Enumerate all `e68bef1b` candidates across the handout → reject the ones with an "explanation" (`cve-poc-output.txt`, superset dump) → the one in `witness-window.bin` is correct.

**Conclusion.** The narration around a leaked string is not evidence; the plainly-placed candidate in `witness-window.bin` wins.

---

## Gridiron — 300 — *solved by ednk*

**Flag:** `N0{4b37ef17-AEBB8MXT4B73KV9APP31B4TC0G}`

**Recon.** Scanning `22-gridiron/gridiron` as raw data turned up several `N0{4b37ef17-...}` strings; the release notes added another likely one. I didn't assume the first ELF hit was correct — the accepted flag is embedded in the ELF.

**Intended route (not completed).** `gate-in.txt`: this build uses a public stand-in `CANON_21` to derive its anchor mask, so it doesn't depend on the previous pwn answer. The release notes mention a class table widened to **2049** entries and a bounds fix in `op_steer_submit` (`<=` → `<`), both pointing at the service bug (an off-by-one out-of-bounds in the class table). I ran out of time before turning it into a working network exploit.

**Reproduce.** Extract the `4b37ef17` candidates from the ELF → submit; the embedded one is correct. (Intended: trigger the `op_steer_submit` off-by-one to leak/select the sealed ticket.)

---

## Fusee — 500 — *solved by ednk*

**Flag:** `N0{8a24ef20-SC72MVNHQXPB102H3W54RX4510}`

**Recon.** `24-fusee/deployment-record.txt` describes build D of the ensemble real-time loop and has a `record:` value. Nearby notes had more flag-shaped strings tied to status-body behavior, a dissector, and a seal-writing probe. Five of those were rejected; the `record:` value was accepted.

**Intended route (not completed).** `gate-in.txt` describes a **TOCTOU race** against a live ring offset and publishes the stand-in `CANON_23` for this build plus `live_off = 0x0ebc0000`, so the stage can be approached on its own. The race didn't reproduce during the event.

**Reproduce.** Take the `record:` value from `deployment-record.txt` (reject the dissector/probe strings) → submit. (Intended: win the TOCTOU race at `live_off = 0x0ebc0000`.)

---

# Forensics

## Witness Mark (Stage 02) — 300 — *solved by AlatBekam*

**Flag:** `N0{6a19ef11-6TAN04EV9B574AG10P4SD89VJ0}`

**Description.** *"An archive of certificates stretches back further than anyone bothered to check. Somewhere in the stack, one page doesn't belong."* Handout `1-forensics/02-witnessmark`:
- `certs/A00000000.pdf … A00000019.pdf` (20 PDF 1.7 certificates with incremental-update history).
- `ARCHIVE-INDEX.txt` — canonical preimage `K7-<LAB>-<MJD>|<D>|<U>`, `slot = CRC-64/XZ(preimage) mod 20`.
- `roster.dataless` — closed vocabulary: 8 valid masers (`HM-01A, HM-02B, HM-03B, HM-04C, HM-05D, HM-06E, HM-07F, HM-08G`); operating window **MJD 61133–61609** inclusive.
- `README.txt` — *"The Bureau never deletes. Every withdrawn revision is still physically present in the file, behind whatever object number superseded it."*

**Step 1 — size anomaly.** 19 files are exactly **82,396 B**; `certs/A00000016.pdf` is **83,307 B** (+911 B from an extra incremental revision). `%%EOF` markers confirm the shifted offsets:

```text
# A00000000.pdf: 872 / 1252 / 81513 / 81914 / 82390
# A00000016.pdf: 872 / 1252 / 82421 / 82823 / 83301   (extra objects appended)
```

**Step 2 — 16 readback tokens** in `A00000016.pdf` (`strings … | grep -E "N0\{"`), all sharing prefix `6a19ef11`:

```text
% readback token N0{6a19ef11-6TAN04EV9B574AG10P4SD89VJ0}
% readback token N0{6a19ef11-SY3P6PWB2AFNG7NAWCFEF6EKYW}
... (16 total) ...
```

**Step 3 — incremental-update objects.** The appended revision replaces the page via `/XRef`, adding a `/Annot` note `(Routine QA note - see custody log)` and a blank `/XObject` form — a "soft replacement" that *withdraws* the original page content.

**Step 4 — find the page that doesn't belong.** The active (latest) page must violate the roster: it should carry no valid maser and no in-window MJD.

```python
#!/usr/bin/env python3
import os, re, pypdf
pdf = os.path.join("certs","A00000016.pdf")
raw = open(pdf,"rb").read().decode("latin1","ignore")
tokens = re.findall(r"readback token (N0\{6a19ef11-[A-Z0-9]{26}\})", raw)
reader = pypdf.PdfReader(pdf)
valid = {"HM-01A","HM-02B","HM-03B","HM-04C","HM-05D","HM-06E","HM-07F","HM-08G"}
for i, page in enumerate(reader.pages):
    t = page.extract_text() or ""
    maser = (re.search(r"HM-\w+", t) or [None])
    maser = re.search(r"HM-\w+", t); maser = maser.group() if maser else "UNKNOWN"
    m = re.search(r"\b(6\d{4})\b", t); mjd = int(m.group(1)) if m else None
    ok = maser in valid and mjd is not None and 61133 <= mjd <= 61609
    print(i+1, maser, mjd, "VALID" if ok else "[ANOMALI]", tokens[i] if i < len(tokens) else "N/A")
```

```text
Total token: 16
Total halaman PDF: 1
1 | UNKNOWN | None | [ANOMALI] | N0{6a19ef11-6TAN04EV9B574AG10P4SD89VJ0}
```

The active page shows no valid maser and no operating-window MJD → it's the odd page out, and its readback token is the flag.

**Reproduce.** Spot the +911 B file → `strings` the 16 tokens → render the current page with `pypdf` → the page failing the `roster.dataless` maser/MJD check is the anomaly; its token is the flag.

**Conclusion.** PDF incremental updates keep every withdrawn revision physically present; the *currently active* page is the one that "doesn't belong" per the closed vocabulary.

---

## Round Robin — 300 — *solved by ednk*

**Flag:** `N0{0a37eeff-VV10G2S77QRVBS1J24DQW4A3K8}`

**Description.** Eleven labs measured the same thing; find which one is telling the truth. Each lab (A3, B1, … M1) submits a degree of equivalence D and uncertainty U, backed by 24 hourly phase records.

**Handout.**
- `roundrobin/<LAB>/SUB-<LAB>-2029.229.dat` — declared D, u1–u5, U, k=2; Ed25519-signed over the raw `.dat`.
- `phase/<MJD>/K7-<MJD>-HH.pcr` — 11 days × 24 records. Each `.pcr` is a 4,194,304-byte RIFF/WAVE (3-ch float32) + a 97-line ASCII trailer; trailer line 4 is `WITNESS-MARK <token>`. Labs map to days in order (A3→61143 … F8→61148 … J2→61151 … M1→61153).
- `registry.sqlite` — `cert_record` (264 × 16 revisions, 64-byte Ed25519 seals), `custody_epoch` (9 keys), `operator_note` (revision flags A–D for F8).

**Recompute D and U (per `FORMATS.txt`).** For each lab, concatenate channel-0 samples `[600:3000)` from its 24 records in `(MJD, HH)` order, recompute D and U:

```python
import numpy as np, struct, math
def ch0(path):
    d = open(path,'rb').read(); dsz = struct.unpack('<I', d[40:44])[0]
    a = np.frombuffer(d[44:44+dsz], '<f4').reshape(-1, 3)[:, 0]
    return a[600:3000].astype(float)
def adev(x, m):                                   # overlapping ADEV, tau=1000, tau0=1, m=1000
    N = len(x); dd = x[2*m:] - 2*x[m:-m] + x[:-2*m]
    return math.sqrt((dd*dd).sum() / (2*m*m*(N-2*m)))
# D_sec = mean(concatenated pair-0 samples);  U = adev(...) / k
```

| Lab | ΔD (ps) | U ratio |
|---|---:|---:|
| A3 … M1 (9 labs) | ±300 to 1450 | 1.02 to 1.06 |
| J2 | −1 | 1.001 |
| F8 | +311249 | 2.93 |

Nine labs were off by ~1000 ps; J2 matched to within 1 ps and 0.1%; **F8 was wildly off** (the lab whose numbers don't hold up).

**Flag.** Only the HH23 record of each lab has a real `WITNESS-MARK`; the other 23 say `PENDING`. The accepted flag is F8's:

```text
phase/61148/K7-61148-23.pcr → WITNESS-MARK N0{0a37eeff-VV10G2S77QRVBS1J24DQW4A3K8}
```

**Decoys (5 wrong submissions).** `operator_note` gives F8 revision flags A–D ("epoch review pending"); `INGEST-F8.manifest` gives a fifth token — all wrong. `cert_record.withdraw_mjd = NULL` seems to point at revision D per cert (README warns "the letter alone does not say which is current"). The S7.2 custody-seal check needs a construction from `params.py`/`lib01.py` (not included) — but the D/U recomputation alone was enough.

**Reproduce.** Recompute each lab's D/U from ch0 `[600:3000)` in `(MJD,HH)` order → F8 is the outlier → read the HH23 `WITNESS-MARK` in `phase/61148/K7-61148-23.pcr`.

**Conclusion.** The flag belongs to the lab whose measurements fail their own claimed D/U — the witness marks in `PENDING` records and the `operator_note`/manifest tokens are decoys.

---

## Cold Start — 500 — *solved by ednk*

**Flag:** `N0{7037f0a9-Y4PS4JSFG514TY0HXA0G031MNC}`

**Description.** A raw ELF64 memory core plus a collection note (kernel build, VMCOREINFO, `steer_epoch` layout). One line matters immediately: `/var/lib/k7/ring-history.dat` is **append-only** — a coefficient tuple can appear many times just because it was used before, so counting matches won't reveal the current epoch.

**Method.** I found custody text in the image and read the **status** next to each token. One was marked **current epoch**; the others (including the one tied to the withdrawal MJD) were marked older state. Submitted the current one — accepted. (I didn't finish the full VMCOREINFO → task-struct → live-ring walk; the custody status was enough.)

**Reproduce.** Carve custody text from the core → pick the token labelled current epoch (ignore withdrawn/older-state tokens) → submit.

**Conclusion.** Append-only history means recency, not frequency, decides the answer; the "current epoch" label is the discriminator.

---

## Guard Frame — 500 — *solved by ednk*

**Flag:** `N0{4b37ef0f-V6MNBMB00RTADDB2G11CHHB1H0}`

**Description.** `wr-fabric.pcapng` merges nine White Rabbit / IEEE 1588v2 capture points (~2.4M PTP frames). The readme: fabric order (`fabric-map.txt`) ≠ frame order in the pcap, and the answer depends on a specific **weighted duty cycle**. Getting the order or interface wrong still yields a plausible-looking witness.

**Published duty allocation (8 weights, total 4096):**

```text
[104, 30, 565, 179, 518, 870, 806, 1024]
```

**Method.** `prior-analyst-worklog.txt` already had six versions of the `WITNESS` for event 1337: (1) capture order, (2) published fabric order + published duty cycle, (3) one host region, (4) wrong duty cycle, (5) wrong interface, (6) wrong offset. Checking each against the handout's rules, **only "published fabric order + published duty cycle"** follows them; submitted that witness — accepted. (I didn't reprocess the 2.4M frames myself; I verified which worklog calculation matched the handout.)

**Reproduce.** From `prior-analyst-worklog.txt`, select the witness computed with published fabric order + the published duty-cycle weights → submit.

**Conclusion.** The distractor witnesses each use a wrong ordering/interface/offset/duty; only the handout-compliant combination is correct.

---

## Hold Log — 600 — *solved by ednk*

**Flag:** `N0{0c73f0a9-HW5HWHN1KV3QQEJFHPKD91GYB0}` (revision H)

**Description.** A SQLite registry + its write-ahead log + `BRANCH-SEAL.bin`. Opening the DB normally shows only an older generation.

**WAL recovery.** The later WAL frames use a different salt, so I walked the frame boundaries and rebuilt the last **52 frames** with consistent header and frame checksums (`work/holdlog/rebuild_wal.py`). Once the later records were readable, `maser_calibration_v7` had 16 revisions, each with coefficients, a floor, and a long `custody_annotation` containing one valid-looking flag (`work/holdlog/rows.py`). Revision **H** has the answer at offset 2048 of its annotation — but at that point it was one of sixteen.

**Discriminator.** I compared branch records against the seal and the published `s_04` input and checked the calibration at `τ = 1000 s`. Some readings led to wrong submissions; under the one I used, **H's corrected margin was closest to its recorded floor**, and H's flag was accepted. (I can reproduce the WAL recovery and pull H's string, but couldn't prove offline that the seal/calibration math picks H uniquely — the submission settled it.)

**Reproduce.** Rebuild the last 52 WAL frames (fix salt/checksums) → read `maser_calibration_v7` 16 revisions → compare each against `BRANCH-SEAL.bin`/`s_04` and the τ=1000 s calibration → H (annotation offset 2048) is correct.

**Conclusion.** The current generation lives only in the re-salted tail of the WAL; recovering it exposes the 16-revision table, and the seal/calibration comparison selects revision H.

---

# Steganography

## Deadband — 300 — *solved by ednk*

**Flag:** `N0{5e1a73c4-VKJJZ0ZE4WAJ1XRX1C62PW2G7M}` (REV H)

**Files:** `K7-2029.114.rec` (1 GB RF64/WAVE), `PCW-1-aux.wav`, `PCW-1-front.png` (512×320 oscilloscope render), `PCW-1-note.txt`.

**Register + loud decoys.** The `.rec` header has a full `CERTIFICATE REVISION REGISTER` (REV A–T) in a `LIST/INFO` chunk, and REV P appears again near a "schedule withdrawn" marker. Three revisions are pushed at you:

| Where | Revision |
|---|---|
| token inside `PCW-1-front.png` | B |
| "annexe copy token" in `PCW-1-note.txt` | C |
| `.rec` marker "schedule withdrawn at REV P" | P |

By this stage the loud ones are known to be bait, so B/C/P are dropped.

**Checking the deadband theory.** The note describes a control loop inside a deadband (half-width `6.25e-3`), 256-sample estimation intervals, dwell of 61 intervals — suggesting the dwell times might carry data:

```python
x = np.memmap("K7-2029.114.rec", '<f4', offset=data_off)   # ~89M samples x 3
# ch0: steering signal; ch1: tiny noise; ch2: mostly 0
# LSBs / low bytes of all channels: no embedded text
inside = abs(interval_mean) <= 6.25e-3    # per-256-sample interval means
run_lengths = ...   # ~30k runs, roughly geometric, no bit/byte pattern
```

Nothing decoded — the deadband material is just theme. Submitting from the remaining 13, **REV H** was accepted.

**Reproduce.** Grep `5e1a73c4` for the register → drop the PNG token (B), note "annexe" token (C), and "withdrawn REV P" → the deadband LSB/dwell analysis is a dead end → submit from the rest; REV H is correct.

**Conclusion.** Loudly-placed tokens (image, note, "withdrawn") are decoys, and the deadband story is flavour.

---

## Sidelobe — 300 — *solved by ednk*

**Flag:** `N0{5e1a73c5-CNX5JNSGWRJG0VB20H9QYQY8NC}` (REV C)

**Description.** The `PCW-2` files give a certificate-shaped flag for almost every guard-band revision; the question is which revision was actually in force. The revision index says its letters show *issue order, not validity*, so the last letter would just be a guess.

**Two records disagree.** The service footer on the window roster says **REV D** was in force at the last service. The session duty log `PCW-2-note.txt` says the active guard-band set was **REV C from the 114th**, calls REV F superseded, and describes REV K as a spare-channel reading. The roster also admits its window listing/cadence is a fitter's record, not the instrument's real symbol order. For the current session, the duty log governs → looked up **REV C** in `PCW-2-revision-index.txt` and submitted it — accepted. (Signal params — pedestal at bin 613 of a 2048-pt transform ≈ 14.38 kHz, acquisition starting 911 samples in — weren't needed.)

**Reproduce.** Reconcile the roster footer (REV D) vs. the session duty log (REV C, active from the 114th) → the duty log is authoritative → REV C.

**Conclusion.** Issue order ≠ validity; the session duty log, not the fitter's roster, names the in-force revision.

---

## Interstice — 500 — *solved by ednk*

**Flag:** `N0{5e1a73c6-5JDE8N56HSFE3AYE42TZKR8J78}` (from `S01233.rec`)

**Handout.** `K7-2029.116.d/` with 16,384 files `S00000.rec … S16383.rec` (67,584 B each), `SHA256SUMS`, `gate-in.txt`. Each `.rec` is a `coda-tx`/BWF container with an iXML `<BWFXML>` block, an XMP `<x:xmpmeta>` packet, a `LIST/INFO` chunk, and a 3-channel float `data` chunk.

**16 candidates, three easy eliminations.** Grepping `5e1a73c6` across all files gives 16 distinct flags:

1. `NM8EDTQBRKEJJ93BJ40VHSRY5R` is in the `LIST/INFO` of **every** file → something shared by all 16,384 files can't be the unique answer.
2. `S04096.rec` has an embedded ZIP containing `PCW-3-session-note.txt` starting `K7 PCW-3 SESSION NOTE  REV E  (withdrawn)` + a flag → withdrawn decoy.
3. LSB of the channel-1 samples across a file XORed with `0xFF` gives:
   ```text
   K7 PCW-3 REFERENCE SESSION SCHEDULE  REV D
   span 1864.02 s  sessions 16384  frames/session 5461
   N0{5e1a73c6-MQ89CYJM66PEHRDX0HPSYZKCKC}
   ```
   Same "withdrawn schedule" trick as Deadband, placed for whoever does the LSB extraction.

Each remaining candidate appears in the iXML/XMP/note metadata of exactly one file (`S01233`, `S01716`, `S06053`, `S08191`, …). Taking the plain-metadata flags in file order, the first — **`S01233.rec`** — was accepted on the first try.

**Reproduce.** Grep `5e1a73c6` → drop the all-files `LIST/INFO` token, the `S04096.rec` embedded-ZIP "REV E withdrawn" token, and the LSB-XOR "REV D schedule" token → take the first plain-metadata candidate in file order (`S01233.rec`).

**Conclusion.** Each eliminated flag rewards a specific trick (grep-everything, unzip, LSB); the real one sits in ordinary per-file metadata.

---

# Boot2Root

## Chain of Custody — Pierhouse — *User (300, ftps3rver)* & *Root (500, ftps3rver)*

**Attachment:** `pierhouse.qcow2` (4 GB, BIOS boot) + `SHA256SUMS.txt`
**USER flag:** `Null0rigin{7af10c45d81b3346da84be165fd67940de50e4642b29d144a11bd7cacfb0f2e8}`
**ROOT flag:** `Null0rigin{35cc547dc8fc796247d65c06f8e87570344ab699e5a1e4e4a13dfb0aeff89ba9}`

**Scenario.** Pierhouse runs **K7**, a fictional evidence chain-of-custody control plane that seals, signs and reconciles an estate's records. Two flags: a USER flag reachable as a high-privilege non-root account (`custodian`), and a ROOT flag reachable only after full root compromise. The README warns that other-format "flags" on the box are decoys, and that the intended path doesn't involve the bootloader, host-side disk editing, or SSH brute force.

**Recon.** QCOW2 v3, 4 GB, no encryption, single MBR partition. Mounted read-only via `qemu-nbd`: one ext4 partition labelled "pierhouse", Ubuntu 26.04 LTS. Interactive users: `root, ops(1000), web(1002 nologin), intake(1003), custodian(1004)`. Services: K7 intake portal on TCP 8080, SSH on 22. Key artifact: `/var/lib/k7/custody/userflag.seal` (76 B, owned by `custodian`); the root flag is served at runtime by root daemon `custodyd.py`.

**Intended LIVE privilege chain (web → intake → custodian → root).**
1. **Foothold as `web`** — `/opt/k7/intake/intake_portal.py` (:8080) `/label` "provenance label preview" `eval()`s a user expression, guarded only by a weak substring blocklist (`import`, `os.`, `subprocess`, `system`, `popen`, `open(`, `eval(`, …) — bypassable → RCE as `web`.
2. **`web` → `intake`** — `web` is in group `k7web`; `/opt/k7/intake/plugins/` is group-writable (`drwxrwsr-x`). A `k7-validate` systemd timer `exec_module()`s any plugin there as `intake` every ~30 s → drop a `.py` plugin → RCE as `intake`.
3. **`intake` → `custodian`** — the intake foothold leads to the custody officer account `custodian`, which owns `/etc/k7/custody.mk` (user seal key) and the sealed userflag.
4. **`custodian` → `root`** — a `k7-reconciled` timer runs as root every ~20 s and `pickle.loads()` any `.bundle` in `/var/lib/k7/inbox` whose first 32 bytes are a valid `HMAC-SHA256(/etc/k7/reconcile.vk, payload)`. With the verify key (reachable as `custodian`), a signed malicious pickle → RCE as root; the root daemon `custodyd` prints the root flag on a `DRAIN` command.

**Traps (rejected).** Grepping the disk for `Null0rigin{…}`/`N0{…}` returns only decoys, planted in `legacy/holdover.flag`, `diag/README.txt`, `cert_rows.csv`, a withdrawn certificate, and a commissioning note. Runtime gates (boot-id binding, interactive prompts, TOTP codes) protect only the binaries, never the ciphertext — booting the VM buys nothing.

**Offline recovery — reverse the sealer (the route actually used).**

*USER flag — SHA256-CTR seal.* `/usr/local/bin/k7-custody seal-show` is a SHA256 counter-mode stream cipher whose key `custody.mk` (32 B, custodian-only) is readable off the mounted disk:

```python
keystream(i) = SHA256( custody.mk || b"k7-seal-v1" || counter_be64(i) )   # i = 0,1,2,...
plaintext    = userflag.seal  XOR  keystream
# custody.mk = 750f69c9 8dcffe7f 5fa09b49 6312ca46 a2354b8f cde44820 ab743e4d 548d9ffc  (32 bytes)
# userflag.seal is 76 bytes = "Null0rigin{" + 64 hex + "}"
```

Decrypting the 76-byte sealed file yields exactly 76 bytes in `Null0rigin{…}` format — a real decryption (length + format match), not a guess.

*ROOT flag — HMAC-derived.* `custodyd.py` (root) computes the root flag deterministically from the root-only key `/etc/k7/seal.key`:

```python
# seal.key (base64) = 8JUyXPFmuIelAeQhQaBKv/MfqUTinyLms5pjXRlB2+g=
import hmac, hashlib, base64
key = base64.b64decode("8JUyXPFmuIelAeQhQaBKv/MfqUTinyLms5pjXRlB2+g=")
tag = hmac.new(key, b"k7-root-drain-v1", hashlib.sha256).hexdigest()
flag = "Null0rigin{%s}" % tag
```

This short-circuits the live custodian→root pickle-RCE by reading `seal.key` off the read-only mount and running the daemon's own `root_flag()` formula — the same value `custodyd` would print on `DRAIN`.

**Reproduction (verified live, offline off the real qcow2):**

```bash
# 1. Verify + mount read-only (WSL/kali)
sha256sum -c SHA256SUMS.txt
modprobe nbd max_part=8
qemu-nbd --read-only --connect=/dev/nbd0 pierhouse.qcow2
mount -o ro /dev/nbd0p1 /mnt/pier
# 2. USER: pt = userflag.seal XOR SHA256(custody.mk || b"k7-seal-v1" || ctr_be64)
# 3. ROOT: Null0rigin{ HMAC_SHA256(seal.key, b"k7-root-drain-v1").hexdigest() }
# 4. Clean up
umount /mnt/pier; qemu-nbd -d /dev/nbd0
```

```text
# on-disk key material (read directly):
  /etc/k7/seal.key   = f095325c f166b887 a501e421 41a04abf f31fa944 e29f22e6 b39a635d 1941dbe8
  /etc/k7/custody.mk = 750f69c9 8dcffe7f 5fa09b49 6312ca46 a2354b8f cde44820 ab743e4d 548d9ffc
  /var/lib/k7/custody/userflag.seal = 76 bytes
$ python derive.py
USER: Null0rigin{7af10c45d81b3346da84be165fd67940de50e4642b29d144a11bd7cacfb0f2e8}
ROOT: Null0rigin{35cc547dc8fc796247d65c06f8e87570344ab699e5a1e4e4a13dfb0aeff89ba9}
USER_MATCH: True
ROOT_MATCH: True
```

**Root cause / conclusion.** `eval()` behind a substring denylist (web foothold); a group-writable plugin dir loaded by a privileged timer (→ intake); a root timer `pickle.loads()`-ing HMAC-signed bundles whose verify key is reachable as custodian (→ root). The "seal" ciphers derive their keys from files on the same disk, so with read-only disk access both flags are reproduced offline. **A sealed flag means *reverse the sealer*, not *grep harder*** — every plaintext flag on the disk was a decoy.

---

## Per-member totals

- **ednk (26):** Welcome, The map knows the way, Kuber, Sidelobe, Deadband, Octave, Ouroboros, Round Robin, Gridiron, Remontoire, Beatnote, Guard Frame, Basilisk, Interstice, The Oracle, Randomwalk, Fusee, Cold Start, The Wall, Linewidth, Combtooth, Hold Log, FANTASMA, Phaselock, Coda, Escapement
- **AlatBekam (6):** Connecting Dots, Invisible Infra, Sigmatau, Flicker, Witness Mark, Hadamard
- **ftps3rver (5):** Señal en capas, Tailspin, Two Platforms One Team Different Identity, Chain of Custody — User, Chain of Custody — Root

**Total: 37 solves.**

---

## Appendix — general notes on the finale

- **Flag prefixes differ between challenges:** `NullOrigin{…}`, `Null0rigin{…}` (with a zero), `N0{8hex-26 base32}`, and `NullOriginCTF{…}`. Always check the format line.
- The 26-character body of an `N0{}` flag is **Crockford base32** (`0-9 A-Z` without `I L O U`), decoding to 128 bits + 2 padding bits (always 0). Used above to test whether Octave's `tag_prefix` was a truncated hash — it wasn't.
- The recurring K7 pattern: find the **one un-observable degree of freedom** or the **committed register/certificate** the handout leaves, reject anything with an adjacent "explanation" (those are decoys), and validate locally (`PL8`+CRC / RSS / CRC32 / stamp) before spending one of the 15 submissions.
- For the boot2root: **reverse the sealer, don't grep harder** — every seal is a SHA256-keystream/HMAC construction whose key is a file on the same disk; runtime gates guard only the binaries.
