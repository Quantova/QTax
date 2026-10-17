# QTax

QTax is a post quantum tax integrity layer for governments. It seals every tax filing, electronic invoice, invoice claim, assessment and refund at the moment it is made, so a tax authority, its auditors and the courts can later prove that no record was altered, backdated or invented, while taxpayer data never leaves the authority. Every record is signed with the Module Lattice Digital Signature Algorithm, parameter set 65, as standardised in FIPS 204, and can carry a Qstamp time proof recorded on the Quantova network under the QTax record kind.

QTax is part of QGov, the government branch of the Qstamp family.

## What QTax is

Tax fraud and tax corruption rely on records that change after the fact. A return amended without trace, an invoice that was never issued but is used to reclaim tax, an assessment reduced after it was decided, a refund paid without a valid basis or paid twice. Each depends on a record that its custodian can quietly rewrite.

QTax removes that possibility. The intake system of the tax authority seals each return when it is received and links every amendment to the version it replaces. The certified invoicing system of a seller seals each invoice when it is issued, naming the buyer by key, and the buyer seals its claim against that exact invoice. An authorised assessor signs each assessment against the sealed filing it concerns, and an authorised payment officer signs each refund against the sealed assessment that justifies it. A verifier can then confirm the whole chain without trusting the authority, the seller, the buyer or Quantova Inc.

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

2. Name taxpayers privately. The commitParty function turns a taxpayer identifier into a salted commitment. Only the commitment enters a filing. The authority keeps the identifier and the salt and can prove the link to a court without publishing either.

3. Seal filings. The intake system calls file for every return and every amendment, with the fingerprint of the return document. An amendment names the filing it amends.

4. Seal invoices and claims. The seller's invoicing system calls invoice for every electronic invoice, naming the buyer key, the currency, the total and the tax. The buyer calls claim against the invoice it relies on.

5. Seal assessments and refunds. An assessor calls assess against the sealed filing, stating the refund due. A later decision on the same filing supersedes the earlier assessment explicitly and carries the next sequence number. A payment officer calls refund against the current assessment, naming the previous refund on the same filing or declaring it the first. Each refund carries its position on the filing and the running total paid, and QTax refuses to sign a refund that would take that total above the refund due.

6. Anchor promptly. A single service with a funded Quantova account anchors new records in batches under the QTax record kind, and each record receives its own receipt. Refunds should be anchored as soon as they are paid, before any later assessment of the same return is decided, because a refund anchored after a later assessment replaced its own cannot be shown to have been paid first and verifies as indeterminate.

7. Verify on demand. Auditors and courts verify any record against the trusted intake, assessor and officer keys, the expected seller and the linked records, with the verify command, the library or the independent procedure below.

## What is published and what stays private

Returns, invoices, assessments and taxpayer identities stay with the authority and the certified providers. Records hold only SHA3 fingerprints of documents, salted commitments to taxpayers and the key identifiers of the parties.

When a record is anchored, only a 32 byte Qstamp commitment reaches the chain. It is derived from a salted fingerprint of the signed record and cannot be reversed into any field of the record.

## Cryptographic construction

1. Keys. Keys are 32 byte seeds from which ML-DSA-65 key pairs are derived by the key generation procedure of FIPS 204. A key identifier is the SHA3 hash with a 256 bit output of the ASCII label quantova/qtax/key/1, the byte 0x00 and the 1952 byte public key.

2. Party commitments. A taxpayer is named by the SHA3-256 hash of the ASCII label quantova/qtax/party/1, the byte 0x00, a random 32 byte salt and the identifier in Unicode normal form C.

3. Statements. Each statement is a canonical binary encoding that begins with the ASCII bytes QTAX and the version byte 1, followed by the statement type and its fields in a fixed order. Every field is an unsigned 16 bit big endian length followed by its bytes, an optional reference is an empty field when absent and a content size is an unsigned 64 bit big endian integer, so every statement has exactly one encoding. Amounts are whole numbers of minor units with no leading zeros, and a currency is three capital letters, which QTax checks for form only, so the integrating system should use ISO 4217 codes.

4. Signatures. Statements are signed with ML-DSA-65 in its hedged form under the FIPS 204 context string quantova/qtax/1, which separates QTax signatures from every other SDK of the family and from every other use of the algorithm.

5. References. A record is referenced by the SHA3 hash of the label quantova/qtax/ref/1, the byte 0x00, the encoded statement and its signature. Amendments, claims, assessments and refunds name the records they rely on by these references, so each relies on one exact signed record that existed before it was signed.

6. Chains. A filing names the original return it belongs to, which is empty for an original return and is carried unchanged through every amendment. An assessment carries the reference of the filing it assesses, the original return, a sequence number from one on that return and the reference of the assessment it supersedes, which is empty only for the first. A refund carries the original return, the reference and sequence number of its assessment, its own sequence number on the return, the reference of the previous refund, which is empty only for the first, and the running total paid on the return including itself.

7. Anchor. To anchor a record, QTax stamps the SHA3 hash of the label quantova/qtax/anchor/1, the byte 0x00, the encoded statement and its signature as a Qstamp record of kind 1101.

## Rules applied by verification

1. The expected record type is required, so a record of one type can never be presented as another, and options that do not apply to that type are refused.
2. The record is well formed and signed by the key it names.
3. Filings are signed by a trusted intake key, assessments by a trusted assessor key, refunds by a trusted officer key and invoices by the expected seller. The three lists of trusted keys must not share a key.
4. A linked record is exactly the one referenced, validly signed and signed by a trusted key of its role. An amended filing concerns the same taxpayer, period and form.
5. Each record is dated no earlier than the record it relies on, with no allowance, and no record is dated more than five minutes after the time of verification.
6. When documents are supplied, their fingerprints match the signed fingerprints.
7. A superseding assessment follows the assessment it supersedes on the same original return, in the same currency.
8. A refund is verified with its assessment, the filing that assessment concerns and, when that filing is an amendment, the original return, which must be an original filing for the same taxpayer, period and form. The filing, the assessment and the refund are signed by trusted intake, assessor and officer keys, three different keys, and all name the same original return.
9. A refund is within the refund due on its assessment. Every earlier refund on the return is supplied, validly signed by a trusted officer and continues the chain in position, total, currency and assessment order. Any supplied refund or assessment that is malformed, untrusted or for another return makes the result invalid, and so do two different supplied refunds, or two different supplied assessments, in the same position.
10. When other assessments of the return are supplied, a refund, or any earlier refund of its chain, paid after a later assessment replaced its own assessment is invalid, every refund of the chain is within the refund due on its own assessment, and a refund anchored after that replacement is indeterminate, because it cannot be shown to have been paid first.
11. A refund or an assessment is valid only when the verifier declares that every refund and assessment it holds for the return was supplied. Without that declaration the result is indeterminate, and an assessment is indeterminate when a later assessment of the same return is supplied, because it has been replaced.
12. Each anchor is verified under the QTax record kind with a SHA3 digest, and the stated time is not later than the anchor time, allowing five minutes. An anchor more than twenty four hours after the stated time, unless another limit is given, or later than a given verification time, does not prove the stated time and makes the result indeterminate.

A result is valid only when the trusted keys are given, the linked records are supplied, the return document is supplied for a filing, the earlier refunds on the return are supplied for a refund after the first, the original return is supplied when the filing is an amendment, the verifier declares the records it holds complete for a refund, and every record is anchored. When any of these is missing the result is indeterminate rather than valid. A record verified with anchoring not required proves only who signed it and what was signed, and its stated time is the claim of its signer.

## Trust model of this release

This release anchors on the live Quantova network Q-test-net-1. The signing module is compiled from the Quantova Q-Crypto library, which follows FIPS 204 and FIPS 202 and has been tested against the NIST vectors. It has not been validated under FIPS 140-3. Anchor times are confirmed by the endpoints a verifier queries and are accepted only when at least two endpoints run by different operators agree. Verification names the endpoints it consulted and says whether they are the official endpoints of the network, and a verifier who needs independence from any single operator should query several independent endpoints.

A sealed record proves who signed it, what was signed and when it was anchored. Each check is made from the records a verifier is given. Two refunds in the same position of a chain, or a refund against a replaced assessment, are detected only when the conflicting record is supplied, so auditors should obtain every record the authority holds for a return, including its amendments. A buyer may claim the same invoice more than once, and repeated claims are a matter for the authority to examine. A taxpayer commitment is the same in every record that uses the same salt, so records about one taxpayer can be linked by anyone who sees them, and anyone who obtains the salt can test guesses of the identifier, so salts must be protected like the identifiers themselves. Each return must be received once as an original filing. Two original filings with the same taxpayer, period and form are treated as two separate returns with their own chains, and preventing them is a duty of the intake system that QTax does not check. Verifiers must keep the keys of retired officials in the trusted lists for as long as records they signed are verified, because a record signed by a key that is not trusted is invalid. A sealed record does not prove that a return is truthful or that an assessment is lawful, which remains the work of the authority and the courts, and it does not detect a transaction that was never recorded. Matching keys to accountable officials and businesses is a matter for the authority, for example through published key descriptions and mandates.

A claim verified with otherClaims, the other claims the authority holds on the same invoice, is invalid when an earlier anchored claim on that invoice exists and indeterminate when the order is not proven, so a verifier should be given every claim held for an invoice.

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
qtax commit-party --identity-file taxpayer.txt --salt-out taxpayer.salt

qtax file --key intake.key --taxpayer-ref <commitment> --period "2026 Q3" --form "VAT return" --content return.pdf --out filing.json
qtax invoice --key seller.key --invoice-id "INV 0042" --buyer buyer.pub.json --document invoice.pdf --currency EUR --total 121000 --tax 21000 --out invoice.json
qtax claim --key buyer.key --invoice invoice.json --out claim.json
qtax assess --key assessor.key --filing filing.json --outcome assessment.pdf --currency EUR --refund-due 5000 --out assessment.json
qtax refund --key officer.key --assessment assessment.json --amount 3000 --first --out refund1.json
qtax refund --key officer.key --assessment assessment.json --amount 2000 --previous-refund refund1.json --out refund2.json
qtax anchor filing.json assessment.json refund1.json refund2.json --seed-file account.key

qtax verify refund2.json --type refund --intake intake.pub.json --assessor assessor.pub.json --officer officer.pub.json --assessment assessment.json --filing filing.json --previous-refund refund1.json --all-supplied
```

The file account.key holds the 32 byte seed of a funded Quantova account, as 64 hexadecimal characters, which pays for anchoring. It is separate from the signing keys of officials.

If anchoring is interrupted after its transaction may have been sent, a pending stamp is kept beside each envelope and the envelopes are not anchored again. Finish with qtax complete, giving the same envelopes in the same order and the pending stamp.

The command exits with status 0 when the result is valid, 1 when it is invalid, refused or the evidence is malformed, 2 when it cannot be decided, and 64 for usage errors. Key and salt files must be readable only by their owner and are never followed through symbolic links.

## Independent verification procedure

1. Decode each public key and signature from base64 and confirm their lengths are 1952 and 3309 bytes.
2. Compute each key identifier from the label quantova/qtax/key/1, the byte 0x00 and the public key, and compare it with the signer identifier and the signing party named in the statement.
3. Encode each statement as described above and verify its signature with ML-DSA-65 under the context string quantova/qtax/1, following FIPS 204.
4. Compute the reference of each linked record and confirm it is the one named, then apply the rules of verification listed above.
5. Compute the anchor value of each record and verify its receipt by the procedure published with Qstamp under record kind 1101.

## Network

The live Quantova network is named Q-test-net-1 with genesis hash ca91e093bb8de33e90db52d7c89876597d14760703793ea7211929e73e613062. Anchors are recorded by the official Qstamp contract on that network. The public endpoint is https://rpc-testnet.quantova.org. Chain data is accepted only when at least two endpoints run by different operators agree. Give them with the rpc or clients option, or with --rpc once for each on the command line. The option trustSingleEndpoint, or --trust-single-endpoint, relies on one endpoint, which can then invent an anchor alone.

## Licence

QTax is created and owned by Quantova Inc. It is licensed under the Apache License 2.0 or the MIT licence, at your option. The full texts are in the files LICENSE-APACHE and LICENSE-MIT, and the notice is in NOTICE.
