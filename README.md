## Abstract

In [https://bitcoin.org/bitcoin.pdf](the original Bitcoin whitepaper), Nakamoto expected the blockchain to become too big to be fitted within a low storage machine. Having this problem in mind, they proposed the Simplified Payment Verification, effectively enabling a client to verify a transaction while only storing the block headers, which drastically reduces the data to store. In order to further reduce the storage required by light clients, e.g. to enable deployment on wearable devices or smart contracts, a more efficient *superlight* client technique was recently proposed in [https://eprint.iacr.org/2019/226.pdf](FlyClient). However, it is still to be shown how a such protocol can be deployed on an already existing chain, without contentions soft or hard forks. FlyClient suggests the use of [https://eprint.iacr.org/2018/087.pdf](velvet forks), a recently introduced mechanism for conflict free deployment of blockchain consensus upgrades -- yet the impact on the security of the light client protocol remains unclear.
    
    In this work, we provide a comprehensive analysis of the security of FlyClient under a velvet fork deployment. We discover that velvet forks expose FlyClient to *chain-sewing* attacks, a novel type of attack, concurrently observed in similar superlight clients. Specifically, we show how an adversary subverting only a small fraction of the hash rate or consensus participants, can not only execute double-spending attacks against velvet FlyClient nodes, but also print fake coins -- with high probability of success.

	We then present a mitigation to this attack and prove its security both under velvet and, more traditional soft and hard fork deployment. Finally, we implement this mitigation in the cross-chain setting: we design and deploy a Bitcoin FC as a smart contract on Ethereum, improving upon the existing [http://btcrelay.org/](BTC-Relay).

## Repository contents

[Report/](Report) contains the files used to create the report, be they .tex files or data files.

[Implementation/](Implementation) contains the Smart Contract files used to deploy the robust-to-chain-sewing-attacks version of FlyClient in the cross-chain setting.

[Demo/](Demo) contains files that have been  used for presenting this project.
