# QTax

QTax is a post quantum tax integrity layer for governments. It seals every tax filing, electronic invoice, invoice claim, assessment and refund at the moment it is made, so a tax authority, its auditors and the courts can later prove that no record was altered, backdated or invented, while taxpayer data never leaves the authority. Every record is signed with the Module Lattice Digital Signature Algorithm, parameter set 65, as standardised in FIPS 204, and can carry a Qstamp time proof recorded on the Quantova network under the QTax record kind.

QTax is part of QGov, the government branch of the Qstamp family.

## What QTax is

Tax fraud and tax corruption rely on records that change after the fact. A return amended without trace, an invoice that was never issued but is used to reclaim tax, an assessment reduced after it was decided, a refund paid without a valid basis or paid twice. Each depends on a record that its custodian can quietly rewrite.

QTax removes that possibility. The intake system of the tax authority seals each return when it is received and links every amendment to the version it replaces. The certified invoicing system of a seller seals each invoice when it is issued, naming the buyer by key, and the buyer seals its claim against that exact invoice. An authorised assessor signs each assessment against the sealed filing it concerns, and an authorised payment officer signs each refund against the sealed assessment that justifies it. A verifier can then confirm the whole chain without trusting the authority, the seller or the buyer, and the time of each record counts as proven only through a finality certificate of the network validators or official endpoints of two independent operators, never through one endpoint alone.

QTax is standalone. It runs on the systems of the tax authority and of the certified invoicing providers, holds keys locally and uses the Quantova network only as a neutral public ledger for time proofs.

## What it detects

1. A return or amendment altered, replaced or backdated after receipt.
2. An amendment presented for a different taxpayer than the filing it amends.
3. An invoice claimed by a buyer that the seller never issued, or claimed by a party that is not the named buyer.
4. An invoice claimed before it was issued.
5. An assessment that does not relate to a sealed filing, or that was decided by a key that is not a trusted assessor.
6. A filing, its assessment and its refund signed by fewer than three different keys.
7. A refund with no sealed assessment behind it, in another currency, or before the assessment was decided.
8. Refunds on one return, including its amendments, that together exceed the refund due on the assessment they rely on.
9. A refund hidden from the chain of refunds on a return, or two different refunds or two different assessments in the same position, once the records held for the return are supplied.
10. A refund paid against an assessment that a later assessment had already replaced, once the later assessment is supplied.
11. A record anchored long after the time it states, which is twenty four hours by default, is not accepted as proof of that time.

## Who uses it

1. Tax authorities that want returns, assessments and refunds to be provable to auditors, tribunals and parliaments.
2. Certified electronic invoicing providers that seal invoices for their clients.
3. Businesses that claim input tax and want proof that each claimed invoice was genuinely issued to them.
4. Supreme audit institutions, anti corruption agencies and tax tribunals that review the conduct of a tax administration.

## How a tax authority integrates QTax

1. Issue keys by role. The authority creates separate ML-DSA-65 keys for its intake systems, its assessors and its payment officers and publishes three lists of trusted keys. A key may appear in only one list, and QTax refuses to sign an assessment with the key that received the filing or a refund with the key that decided the assessment. Certified invoicing providers and registered businesses hold their own keys.

2. Name taxpayers privately. A filing is given the taxpayer identifier and the 32 byte party secret of the authority, and the taxpayerRef is derived from both, so the same taxpayer always receives the same commitment and two returns of one taxpayer can be linked by the authority. The identifier is first made canonical. It is brought to Unicode normal form KC, every decimal digit of any script is replaced by the ASCII digit of the same value, combining marks of the Inherited script are removed, spaces, punctuation and invisible characters are removed, case is folded, and every character is replaced by its prototype in the confusable skeleton of Unicode Technical Standard 39, until the result no longer changes. The salt is the SHA3-256 hash of the ASCII label quantova/qtax/party-salt/2, the byte 0x00, the secret and the canonical identifier, and the commitment is the SHA3-256 hash of the ASCII label quantova/qtax/party/2, the byte 0x00, the salt and the canonical identifier. The filing states the scheme secret-canonical/2 and any other scheme is refused. commitParty with the secret returns the salt and the commitment, so the authority can prove the link to a court without publishing the identifier.

3. Seal filings. The intake system calls file for every return and every amendment, with the fingerprint of the return document. An amendment names the filing it amends.

4. Seal invoices and claims. The seller's invoicing system calls invoice for every electronic invoice, naming the buyer key, the currency, the total and the tax. The buyer calls claim against the invoice it relies on.

5. Seal assessments and refunds. An assessor calls assess against the sealed filing, stating the refund due. A later decision on the same filing supersedes the earlier assessment explicitly and carries the next sequence number. A payment officer calls refund against the current assessment, naming the previous refund on the same filing or declaring it the first. Each refund carries its position on the filing and the running total paid, and QTax refuses to sign a refund that would take that total above the refund due. Signing alone is not a gate against a second refund or assessment at the same position, because two officers who each hold an earlier record can both sign. Give file, assess and refund a ledger, one folder or one store with an atomic compare and swap shared by every signer of the authority, and a record is signed only when it follows the latest record of the return that the ledger holds, while a second first record or a record after a stale previous one is refused with the code QTAX_LEDGER. The ledger also holds the filings of each return under the party secret, the taxpayer, the period and the form. A period is written only as YYYY, YYYY-MM or YYYY-Qn and a form only as a code from the list of form codes the authority gives as forms, so one return cannot be filed twice under two spellings, and a second original return of one taxpayer for the same period and form is refused and only an amendment of the latest filing is signed, and a refund is signed only against the latest assessment of its return that the ledger holds. Each of file, assess and refund needs ledger, or ledger set to false when the integrating system serialises the records of each return itself.

6. Anchor promptly. A single service with a funded Quantova account anchors new records in batches under the QTax record kind, and each record receives its own receipt. Refunds should be anchored as soon as they are paid, before any later assessment of the same return is decided, because a refund anchored after a later assessment replaced its own cannot be shown to have been paid first and verifies as indeterminate.

7. Verify on demand. Auditors and courts verify any record against the trusted intake, assessor and officer keys, the expected seller and the linked records, with the verify command, the library or the independent procedure below.

## What is published and what stays private

Returns, invoices, assessments and taxpayer identities stay with the authority and the certified providers. Records hold only SHA3 fingerprints of documents, salted commitments to taxpayers and the key identifiers of the parties.

When a record is anchored, only a 32 byte Qstamp commitment reaches the chain. It is derived from a salted fingerprint of the signed record and cannot be reversed into any field of the record.

## Cryptographic construction

1. Keys. Keys are 32 byte seeds from which ML-DSA-65 key pairs are derived by the key generation procedure of FIPS 204. A key identifier is the SHA3 hash with a 256 bit output of the ASCII label quantova/qtax/key/1, the byte 0x00 and the 1952 byte public key.

2. Party commitments. A taxpayer is named by the SHA3-256 hash of the ASCII label quantova/qtax/party/2, the byte 0x00, a 32 byte salt and the canonical identifier, where the salt is derived from the party secret of the authority as described above and the filing states the scheme secret-canonical/2.

3. Statements. Each statement is a canonical binary encoding that begins with the ASCII bytes QTAX and the version byte 3, followed by the statement type and its fields in a fixed order. Every field is an unsigned 16 bit big endian length followed by its bytes, an optional reference is an empty field when absent and a content size is an unsigned 64 bit big endian integer, so every statement has exactly one encoding. Amounts are whole numbers of minor units with no leading zeros, and a currency is three capital letters, which QTax checks for form only, so the integrating system should use ISO 4217 codes.

4. Signatures. Statements are signed with ML-DSA-65 in its hedged form under the FIPS 204 context string quantova/qtax/1, which separates QTax signatures from every other SDK of the family and from every other use of the algorithm.

5. References. A record is referenced by the SHA3 hash of the label quantova/qtax/ref/1, the byte 0x00, the encoded statement and its signature. Amendments, claims, assessments and refunds name the records they rely on by these references, so each relies on one exact signed record that existed before it was signed.

6. Chains. A filing names the original return it belongs to, which is empty for an original return and is carried unchanged through every amendment. An assessment carries the reference of the filing it assesses, the original return, a sequence number from one on that return and the reference of the assessment it supersedes, which is empty only for the first. A refund carries the original return, the reference and sequence number of its assessment, its own sequence number on the return, the reference of the previous refund, which is empty only for the first, and the running total paid on the return including itself.

7. Anchor. To anchor a record, QTax stamps the SHA3 hash of the label quantova/qtax/anchor/1, the byte 0x00, the encoded statement and its signature as a Qstamp record of kind 1101.

## Rules applied by verification

1. The expected record type is required, so a record of one type can never be presented as another, and options that do not apply to that type are refused.
2. The record is well formed and signed by the key it names.
3. Filings are signed by a trusted intake key, assessments by a trusted assessor key, refunds by a trusted officer key and invoices by the expected seller. The three lists of trusted keys must not share a key. A trusted key may be given with the period it is trusted for, as key, from and until. A record dated or anchored before from is invalid, a record anchored after until is invalid, and a record without a proven anchor time before until is indeterminate.
4. When the verifier gives keyStatus, a function that answers from the key registry for a key identifier with revoked false, or revoked true and revokedAt in whole seconds, every signer of the record and of the records it relies on is checked. A record anchored before the revocation stays valid, a record anchored or dated after it is invalid, and a record dated before it without a proven anchor is indeterminate. An answer of any other shape, an error or no answer within keyStatusTimeoutMs, ten seconds unless given, leaves the result indeterminate.
5. A linked record is exactly the one referenced, validly signed and signed by a trusted key of its role. An amended filing concerns the same taxpayer, period and form.
6. Each record is dated no earlier than the record it relies on, with no allowance, and no record is dated more than five minutes after the time of verification.
7. When documents are supplied, their fingerprints match the signed fingerprints.
8. A superseding assessment follows the assessment it supersedes on the same original return, in the same currency.
9. A refund is verified with its assessment, the filing that assessment concerns and, when that filing is an amendment, the original return, which must be an original filing for the same taxpayer, period and form. The filing, the assessment and the refund are signed by trusted intake, assessor and officer keys, three different keys, and all name the same original return.
10. A refund is within the refund due on its assessment. Every refund held for the return is supplied as refunds, which replaces the older name previousRefunds that is still read, and every earlier refund is validly signed by a trusted officer and continues the chain in position, total, currency and assessment order. Any supplied refund or assessment that is malformed, untrusted or for another return makes the result invalid, and so do two different supplied refunds, or two different supplied assessments, in the same position.
11. When other assessments of the return are supplied, a refund, or any earlier refund of its chain, paid after a later assessment replaced its own assessment is invalid, every refund of the chain is within the refund due on its own assessment, and a refund anchored after that replacement is indeterminate, because it cannot be shown to have been paid first.
12. A refund or an assessment is valid only when the verifier declares with allSupplied that every refund and assessment it holds for the return was supplied, and gives them, refunds and otherAssessments for a refund and otherAssessments for an assessment. Without that declaration, or with it but without those lists, the result is indeterminate, and an assessment is indeterminate when a later assessment of the same return is supplied, because it has been replaced.
13. Each anchor is verified under the QTax record kind with a SHA3 digest, and the stated time is not later than the anchor time, allowing five minutes. An anchor more than twenty four hours after the stated time, unless another limit is given, or later than a given verification time, does not prove the stated time and makes the result indeterminate. The time of verification is read from the chain unless it is given with at, and when it cannot be read verification stops with an error rather than use the local clock.
14. The whole verification, the chain time, every anchor and every key status, ends within deadlineMs, two minutes unless given and at most one hour. An anchor or key status that was not checked by then leaves the result indeterminate and adds a time limit check, and a chain time not read by then stops verification with an error.

A result is valid only when the trusted keys are given, the linked records are supplied, the return document is supplied for a filing, the earlier refunds on the return are supplied for a refund after the first, the original return is supplied when the filing is an amendment, the verifier declares the records it holds complete for a refund, and every record is anchored. When any of these is missing the result is indeterminate rather than valid. A record verified with anchoring not required proves only which key signed it and what was signed, and its stated time is the claim of its signer.

## Trust model of this release

This release anchors on the live Quantova network Q-test-net-01. The signing module is compiled from the Quantova Q-Crypto library, which follows FIPS 204 and FIPS 202 and has been tested against the NIST vectors. It has not been validated under FIPS 140-3. An anchor time is accepted only when Qstamp proves the anchor, either by a finality certificate checked against a pinned validator roster or by official endpoints of the network run by two different operators. An anchor confirmed by endpoints of one operator, or by endpoints chosen by the verifier, is unproven, is treated as not anchored and makes the result indeterminate, never valid, whatever options are set. While the network has one official endpoint and no pinned roster every anchor is unproven, which is the honest result. Verification names the endpoints it consulted and says whether they are the official endpoints of the network.

A sealed record proves which key signed it, what was signed and when it was anchored. Each check is made from the records a verifier is given. Two refunds in the same position of a chain, or a refund against a replaced assessment, are detected only when the conflicting record is supplied, so auditors should obtain every record the authority holds for a return, including its amendments. A buyer may claim the same invoice more than once, and a claim verified without otherClaims is indeterminate. A taxpayer commitment is the same in every record of that taxpayer, so records about one taxpayer can be linked by anyone who sees them, and anyone who obtains the party secret can test guesses of the identifier, so the secret must be protected like a signing key. Each return must be received once as an original filing. An assessment or a refund is indeterminate unless otherFilings gives the filings the authority holds for the taxpayer, period and form, and when another original return of them was anchored earlier the result is invalid. Every filing carries partySecretId, the id of the party secret it was made with, and a verifier gives partySecretId or partySecret of the authority together with forms, so a filing made through a desk holding another secret is invalid, a filing of the same taxpayer and period under another form is indeterminate and a return filed twice through two offices earns no valid refund. A filing verified without otherFilings is indeterminate, an assessment is signed through the ledger only against the latest filing of its return, and an assessment or refund on a filing that a later amendment replaced is invalid once that amendment is supplied. Verifiers keep the keys of retired officials in the trusted lists for as long as records they signed are verified, with the until time from which the key is no longer trusted, or answer for them through keyStatus, so a retired key cannot sign new records that verify. A sealed record does not prove that a return is truthful or that an assessment is lawful, which remains the work of the authority and the courts, and it does not detect a transaction that was never recorded. Matching keys to accountable officials and businesses is a matter for the authority, for example through published key descriptions and mandates.

A claim verified with otherClaims, the other claims the authority holds by the buyer, is invalid when an earlier anchored claim by the buyer it names exists on that invoice, or on another invoice of the same seller with the same invoice identifier in its canonical form or with the same invoice document, and indeterminate when the order is not proven, so a verifier should be given every claim held for the buyer. The invoices those other claims rely on are given as otherInvoices, and another claim of the buyer whose invoice is not given makes the result indeterminate, so an input tax claimed again through a re-issued invoice is found. Only claims signed by that buyer count, so a claim signed by the seller or by any other key can never make the claim of the buyer invalid. The invoice must be supplied for other claims to be judged, and without it the result is indeterminate. The anchors of at most 16 other claims by the buyer are checked, and when the buyer made more the result is indeterminate unless an earlier one is found among them.

## Threat model

QTax protects filings, invoices, claims, assessments and refunds, the keys of each role, the taxpayer salts, the series ledger shared by the signers of the authority, and the receipts of anchors.

It trusts the intake, assessor and officer key lists and the seller key that the verifier gives, the key registry it consults through keyStatus, the network values pinned in the Qstamp release it depends on, and the storage that holds keys, salts and the ledger. It does not trust the gateway or any endpoint, the holders of records, or any record not signed by a trusted key for its role.

A forged or altered record fails its signature or the reference that a later record names, and a filing, its assessment and its refund must carry three different trusted keys. Signatures use the context string quantova/qtax/1 and anchors use record kind 1101, so a record signed or anchored for another SDK never verifies here, and every anchor is checked against the genesis and contract pinned in the Qstamp release. A hostile gateway cannot make an unproven anchor count, and the time of verification is never taken from the local clock. A record dated before a record it relies on is invalid, and an anchor more than 24 hours after the stated time does not prove that time. The running total stops refunds above the refund due, the ledger refuses a second assessment or refund at a position it already holds, and two different records at one position are invalid once both are supplied. A ledger folder that every user can write, or that lies under a folder another user can change, is refused. A retired or revoked key is closed by a trusted period or by keyStatus, and a record anchored after it is invalid. Input is parsed strictly within fixed size limits, and a verification ends within its time limit however slowly the gateway or the key registry answers.

Left to the integrator are the protection of keys and salts, keeping the ledger folder writable only by the signers and backed up whole, since a folder rolled back or missing a file lets a position be signed again, supplying every record, filing and claim held for a return or buyer, sharing one ledger across every office that receives returns, and the truth of a return or the lawfulness of an assessment.

## Installation

```
npm install @quantovainc/qtax
```

QTax requires Node 20 or later.

## Command line use

```
qtax keygen intake.key
qtax keygen assessor.key
qtax keygen officer.key
qtax keygen seller.key
qtax keygen buyer.key
qtax key intake.key > intake.pub.json
qtax key assessor.key > assessor.pub.json
qtax key officer.key > officer.pub.json
qtax key buyer.key > buyer.pub.json
qtax keygen party.secret
qtax commit-party --identity-file taxpayer.txt --party-secret-file party.secret --salt-out taxpayer.salt

mkdir ledger
qtax file --key intake.key --taxpayer-identity-file taxpayer.txt --party-secret-file party.secret --period 2026-Q3 --form VAT --forms VAT,VAT100,ITR --content return.pdf --ledger ledger --out filing.json
qtax invoice --key seller.key --invoice-id-file invoice-id.txt --buyer buyer.pub.json --document invoice.pdf --currency EUR --total-file total.txt --tax-file tax.txt --out invoice.json
qtax claim --key buyer.key --invoice invoice.json --out claim.json
qtax assess --key assessor.key --filing filing.json --outcome assessment.pdf --currency EUR --refund-due-file refund-due.txt --ledger ledger --out assessment.json
qtax refund --key officer.key --assessment assessment.json --amount-file amount1.txt --first --ledger ledger --out refund1.json
printf 2000 | qtax refund --key officer.key --assessment assessment.json --amount-file - --previous-refund refund1.json --ledger ledger --out refund2.json
qtax anchor filing.json assessment.json refund1.json refund2.json --network testnet --seed-file account.key --trust-single-endpoint

qtax verify refund2.json --type refund --network testnet --intake intake.pub.json --assessor assessor.pub.json --officer officer.pub.json --assessment assessment.json --filing filing.json --refund refund1.json --refund refund2.json --other-assessment assessment.json --other-filing filing.json --forms VAT,VAT100,ITR --party-secret-id $(qtax party-secret-id --party-secret-file party.secret) --all-supplied --trust-single-endpoint
```

The file account.key holds the 32 byte seed of a funded Quantova account, as 64 hexadecimal characters, which pays for anchoring. It is separate from the signing keys of officials.

Notes, invoice ids and amounts are read from files, or from standard input when the file is given as -, so they never appear in the shell history or the process list. Only one value can come from standard input in each command.

The network has one official endpoint today, so the anchor and verify commands above are given --trust-single-endpoint to rely on it. Without that flag they stop, because chain data is accepted only when endpoints of two different operators agree. With it a verification reports INDETERMINATE and exits with status 2, because an anchor confirmed by one operator is unproven. Once the Qstamp release lists official endpoints of two different operators the flag is no longer needed.

The file, assess and refund commands take --ledger with the folder shared by every signer of the authority, as in the example above. The ledger folder records every position already signed, so keep it on storage that only the signing service can write to, never edit or delete a file in it, and back it up as a whole, because a folder that is rolled back or loses a file lets a position be signed a second time. Without --ledger they sign nothing and exit with status 64, unless --no-ledger declares that the integrating system serialises the filings, assessments and refunds of each return itself.

If anchoring is interrupted after its transaction may have been sent, a pending stamp is kept beside each envelope and the envelopes are not anchored again. Finish with qtax complete, giving the same envelopes in the same order and the pending stamp.

The command exits with status 0 when the result is valid, 1 when it is invalid, refused or the evidence is malformed, 2 when it cannot be decided, and 64 for usage errors. Key and salt files must be readable only by their owner and are never followed through symbolic links.

## Independent verification procedure

1. Decode each public key and signature from base64 and confirm their lengths are 1952 and 3309 bytes.
2. Compute each key identifier from the label quantova/qtax/key/1, the byte 0x00 and the public key, and compare it with the signer identifier and the signing party named in the statement.
3. Encode each statement as described above and verify its signature with ML-DSA-65 under the context string quantova/qtax/1, following FIPS 204.
4. Compute the reference of each linked record and confirm it is the one named, then apply the rules of verification listed above.
5. Compute the anchor value of each record and verify its receipt by the procedure published with Qstamp under record kind 1101.

## Network

The live Quantova network is named Q-test-net-01. Its genesis hash and the official Qstamp contract that records anchors are pinned in the Qstamp release this SDK depends on. The public endpoint is https://q-test-net-01.quantova.org. By default verification consults the official endpoints of the network. Every verification names the network its records were anchored on with the network option, or --network on the command line, testnet for the public network or custom for a chain reached only through endpoints the verifier chose, and an anchor recorded on any other network fails. Endpoints chosen by the verifier are given with the rpc or clients option, or with --rpc once for each on the command line, and verification consults them only with trustCustomEndpoints, or --trust-custom-endpoints. An endpoint on a loopback address is refused unless allowLoopback, or --allow-loopback, is set, and an endpoint on a private network address unless it is named in endpointAllowList, or with --allow-endpoint. The option expectedSender, or --expect-sender, names the Quantova accounts entitled to anchor records, and an anchor signed by any other account is invalid. Anchoring accepts chain data only when at least two endpoints run by different operators agree, and the option trustSingleEndpoint, or --trust-single-endpoint, relies on one endpoint for anchoring and for the time of the chain.

## Licence

QTax is created and owned by Quantova Inc. It is licensed under the Apache License 2.0 or the MIT licence, at your option. The full texts are in the files LICENSE-APACHE and LICENSE-MIT, and the notice is in NOTICE.
