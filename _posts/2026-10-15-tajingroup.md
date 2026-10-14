---
layout: post
title: "Pop Smoke: The Wallets Went Quiet Three Days Before the Designation"
date: 2026-10-15
tagline: "What naming a criminal marketplace actually buys, read off the public blockchain"
image: /IMG/101526.png
tags: [Threat Intel, Threat Analysis, Phishing]
---

Something I've not really tried my hand at is [blockchain analysis](https://www.elliptic.co/blockchain-basics/what-is-blockchain-analytics/).  Just one of those things that became a technique long after my career was underway. Never above being an old dog with a new trick, I thought I'd dig into [Tajin Group](https://aviatrix.ai/threat-research-center/tajin-group-chinese-guarantee-marketplace-phishing-money-laundering-2024/) given they'd been in the news lately.

The general background is - on September 6, two TON wallets attributed to Tajin Group sent their newest high-value Telegram collectibles to the same address. Neither initiated another transaction.

Two days later, the U.S. Secret Service helped freeze 52 wallets holding $52.8 million in USDT. On September 9, OFAC designated Xinbi Guarantee, the marketplace associated with Tajin, and the DOJ's Scam Center Strike Force seized infrastructure and digital asset wallets. Treasury puts Xinbi's throughput at more than $24 billion equivalent since roughly 2022. Within hours of the freezes, Xinbi swapped about $2.8 million of what remained into USDD, a stablecoin without a central issuer able to freeze it.

<img width="800" height="450" alt="The Xinbi Tajin Timeline" src="https://github.com/user-attachments/assets/cba4aae5-35f2-4bc6-828b-21c0dec06956" />


The timing is interesting. It isn't proof that Tajin knew the action was coming. The wallets could have been provisioning a new identity, moving assets for another reason, or simply going quiet while the business continued elsewhere. Their public histories can't distinguish between those explanations.

What they can show is the limit of a marketplace-level disruption: the infrastructure can be seized while the merchants who used it remain a separate investigative problem.

The timing caught my attention in Recorded Future's [profile of Tajin Group](https://www.recordedfuture.com/research/tajin-group-gurantee-marketplace), a Chinese-speaking carding and money-laundering vendor. Its report notes that the marketplace Tajin trades on was sanctioned by the UK in March. It was written on a production timeline, not as a live account of the September action. That's understandable, but it changes how to read it: this is a profile of a going concern whose escrow layer was seized shortly before publication.

<br>

**What a guarantee marketplace actually is**

Strip away the branding and it's escrow for people who can't sue each other. Buyers and sellers of stolen card data, laundering services, SIM farms, and scam-center supplies transact through a Telegram-based market that holds funds until both sides are satisfied. Merchants post a cryptocurrency deposit; a burned buyer is compensated out of it. Elliptic's [description of the deposit mechanism](https://www.elliptic.co/insights/elliptic-helps-us-secret-service-freeze-xinbi-scam-marketplace-assets/) explains the business model: the guarantee substitutes for legal recourse.

The deposit is also an advertisement. Tajin's Telegram channel [claims a stake of 208,848 USDT](https://www.recordedfuture.com/research/tajin-group-gurantee-marketplace) on Xinbi, against a few hundred to a thousand for a typical vendor. That's actor marketing relayed by a researcher who saw the channel, as are its claims about 65 banned card BIN prefixes across twelve countries, professional operators, downtime compensation, and cards that supposedly clear in thirty-odd countries.

Insikt Group checked the ban list against payment-fraud data and found it tracked 3DS enforcement rather than issuer fraud flags: 141 of 195 observations carried a 3DS result failing authentication. That corroborates one claim. It doesn't warrant the rest.

<br>

**Who is on the list, and who isn't**

The September 9 SDN additions name Xinbi Guarantee, SafeW Technology Co., Ltd. of Singapore, and Anwen Technology Co., Ltd. of Phnom Penh. The last two were designated for [materially supporting Xinbi](https://ofac.treasury.gov/recent-actions/20260909). SafeW is the encrypted messenger Xinbi began moving its merchant network onto around June 2025; Anwen built XinbiPay. The UK [sanctioned Xinbi in March 2026](https://www.gov.uk/government/news/uk-crackdown-on-vile-scam-centres-steps-up-with-sanctions-on-illicit-crypto-network) as part of an action against what's believed to be Cambodia's largest scam compound.

Tajin Group isn't named in the September 9 OFAC action, nor are its administrators or merchant accounts. Trading on a designated platform doesn't itself designate a vendor. Recorded Future is the only deep source here on Tajin; the sanctions sources concern Xinbi and its enablers. The public chain data doesn't independently establish Recorded Future's attribution.

<br>

**What the chain says**

Insikt Group [attributes two TON addresses](https://www.recordedfuture.com/research/tajin-group-gurantee-marketplace) to the current owner of Tajin's laundering channel and says the pair "sold and purchased more than 100 Telegram usernames and multiple phone numbers." Collectible Telegram usernames are NFTs on TON, bought through Fragment. Those operational choices leave a public ledger.

The two wallets currently hold 21 items in the Telegram Usernames collection: [14 in the first wallet](https://tonapi.io/v2/accounts/UQAXN4aCAbJ_1GK1jA38eOpG-py3MYP3RhAuChCG4HE7oX1S/nfts?limit=1000&offset=0) and [7 in the second](https://tonapi.io/v2/accounts/UQCOe_qYf9xsaQFWbq5Jg-Q0BRP_RwwHYIY1ErS9enJrjgoW/nfts?limit=1000&offset=0). Recorded Future's figure of "more than 100" bought and sold is a cumulative flow, while these counts are current holdings. They aren't directly comparable. The chain doesn't establish where every item went; some may have been sold, moved outside the attributed addresses, or transferred to counterparties.

The accounts report `last_activity` on [September 12](https://tonapi.io/v2/accounts/UQAXN4aCAbJ_1GK1jA38eOpG-py3MYP3RhAuChCG4HE7oX1S) and [September 8](https://tonapi.io/v2/accounts/UQCOe_qYf9xsaQFWbq5Jg-Q0BRP_RwwHYIY1ErS9enJrjgoW), respectively. But every event on either wallet since September 6 is inbound dust flagged `"is_scam": true`: one-nanoton transfers carrying advertising text such as "advertise for thousands of addresses cheap and fast." Those bump the activity timestamp. They say nothing about the operator. The wallets didn't become inactive; they stopped initiating transactions.

The last transaction either wallet initiated was an NFT transfer. The first sent one at 18:23:15 UTC on September 6; the second at 18:26:12 UTC. Three minutes apart, both went to the same address, which received them and [has done nothing since](https://tonapi.io/v2/accounts/0:41386bc2f1ab651a2d5add729a5949411f06fc7e9c370bee66538d35fdea512e/events?limit=3). What moved was a Fine Pen collectible gift bought August 31 for 88 TON, and the anonymous number `+888 0351 2627`, bought that day for 2,999 TON with funds that arrived minutes earlier from an address the API labels `OKX 11`.

<img width="800" height="500" alt="The Tajin Wallet Moves" src="https://github.com/user-attachments/assets/8bc1832f-bbc4-4cd3-aa29-7e17e6f61790" />

So the two attributed wallets consolidated their two newest high-value collectibles into a third address and stopped initiating transactions two days before the Secret Service freezes began at 08:00 UTC on September 8, and three days before the designation.

That's a coincidence in time, not a cause. A collectible gift and an anonymous number are exactly the kind of assets someone might use to stand up a new Telegram identity, so this may have been routine provisioning that happened to fall near a major enforcement date. It may have been a vendor that saw something coming. Operations may simply have continued on addresses nobody has attributed. Two wallet histories can't distinguish between those possibilities, and they say nothing about whether Tajin as a business stopped or carried on. The public chain doesn't show a vendor flinching after the designation, because it doesn't show these addresses doing anything after it.

_Editorial note: TONAPI v2 account metadata, NFT inventories, and event histories checked on 2026-09-15. Username counts were cross-checked with collection-filtered pagination through empty pages. UTC conversions use the raw Unix timestamps. "Operator-initiated" versus "inbound dust" is an analytical classification based on the sender and the API's `is_scam` flag, not a source field. Wallet attribution rests entirely on Recorded Future. Chain data is live._

<br>

**What the designation bought**

Something, and less than the headline suggests.

Elliptic reports that by 16:20 UTC on September 9, Telegram had [deleted Xinbi's central channels and banned its usernames](https://www.elliptic.co/insights/elliptic-helps-us-secret-service-freeze-xinbi-scam-marketplace-assets/). Buying tradable usernames is precisely the operational-security move this ecosystem has converged on. The action immobilized $52.8 million and imposed a compliance obligation reaching every U.S. person, and every entity owned 50 percent or more, directly or indirectly and in aggregate, by blocked persons.

The freezes the day before also prompted a stablecoin migration within hours. Elliptic is careful about what that migration is worth: USDD has no central issuer and no freezing capability, but its decentralization claims are contested and it remains exposed to freezing risk because it is partly collateralized with freezable USDT. Moving from a freezable asset into one backed partly by the same freezable asset is where the pressure lands.

The migration precedent is clear at the marketplace level. Telegram shut Huione Guarantee in May 2025; Elliptic found that [Tudou Guarantee absorbed most of the volume](https://www.elliptic.co/blog/telegram-dark-markets-expand-to-fill-the-gap-left-by-huione-guarantee) and more than doubled its users, inheriting many of the same merchants. Elliptic tracked more than thirty other highly active markets standing by. Xinbi then grew into the space Huione and Tudou vacated and is now itself designated and offline. This is a precedent for marketplace replacement, not evidence that Tajin followed every step of that sequence.

Naming a marketplace removes a node. The merchants aren't the node.

The published Huione totals don't agree, and I'd rather flag that than average them. Elliptic reported [over $27 billion](https://www.elliptic.co/blog/telegram-dark-markets-expand-to-fill-the-gap-left-by-huione-guarantee) in June 2025 and [$31 billion over four years](https://www.elliptic.co/insights/elliptic-helps-us-secret-service-freeze-xinbi-scam-marketplace-assets/) in its later report. FinCEN's [section 311 final rule](https://www.federalregister.gov/documents/2025/10/16/2025-19571/imposition-of-special-measure-regarding-huione-group-as-a-foreign-financial-institution-of-primary) cites Chainalysis at "at least USD 49 billion worth of CVC since 2021." Those are different scopes, methods, and cutoff dates, not the same measurement taken three times. Treat any single throughput figure as an order of magnitude with a source's name attached.

<br>

**Artifacts**

- **Designated 2026-09-09:** Xinbi Guarantee (`xinbi[.]com`); SafeW Technology Co., Ltd. (`safew[.]org`, `safew-app[.]org`); Anwen Technology Co., Ltd.
- **Not designated in that action:** Tajin Group and its associated channels and merchant accounts
- **TON wallets attributed to Tajin by Recorded Future:** `UQAXN4aCAbJ_1GK1jA38eOpG-py3MYP3RhAuChCG4HE7oX1S`, `UQCOe_qYf9xsaQFWbq5Jg-Q0BRP_RwwHYIY1ErS9enJrjgoW`
- **Consolidation destination, 2026-09-06:** `0:41386bc2f1ab651a2d5add729a5949411f06fc7e9c370bee66538d35fdea512e`
- **Collectible number transferred out:** `+888 0351 2627` (bought 2026-08-31 for 2,999 TON)
- **Merchant payment links reported by [Insikt Group](https://www.recordedfuture.com/research/tajin-group-gurantee-marketplace):** `hxxps[:]//payae[.]cc/QTTb209`, `hxxps[:]//payae[.]cc/Qwpf734`, both resolving to merchant pages on `ccavenue[.]ae`
- **Merchant names reported on those pages:** MOON ENTERPRISE TRADING LLC, SUNWEL ENTERPRISE TRADING LLC. Insikt Group did not find either; both names are close to those of real Dubai firms.

<br>

**Conclusion**

I'd keep tracking the wallets, merchant accounts, and identities that operated through Xinbi rather than treating the marketplace's designation as the end of the investigation. The escrow layer was one part of the ecosystem. The merchants' artifacts are another.

Seizing the marketplace doesn't necessarily retire them.

<img src="http://canarytokens.com/tags/static/4szlmnnmyqe3i6tmxmotprxvw/submit.aspx" style="display: none;" />
