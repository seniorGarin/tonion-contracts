<h1 align="center">
    <img alt="TonIon" src="./assets/banner.png" width="540" height="320" />
</h1>

<br/>

TonIon Contracts is a reusable smart contract library and toolkit for the Tact language on the TON blockchain. TonIon aims to provide reliable and efficient contract components to streamline the development of TON-based decentralized applications.

## Document

You can find Tonion documents on **[Tonion docs](https://tonion.tech)**

### Traits
add the `traits (contracts/traits)` to your project `contracts/imports`, then
Import the required contracts and traits in your Tact code.

#### Sample Jetton Master:

```ts
import "@stdlib/deploy";
import "../imports/tonion/JettonMaster.tact";
import "../imports/tonion/JettonWallet.tact";

contract MyJetton with JettonMaster, Deployable {
    total_supply: Int as coins;
    owner: Address;
    jetton_content: Cell;
    mintable: Bool;
    
    init(owner: Address, content: Cell){
        self.total_supply = 0;
        self.owner = owner;
        self.mintable = true;
        self.jetton_content = content;
    }

    override inline fun calculate_jetton_wallet_init(owner_address: Address): StateInit {
        return initOf MyJettonWallet(owner_address, myAddress());
    }

}
```

#### Sample Jetton Wallet:
```ts
import "@stdlib/deploy";
import "../imports/tonion/JettonMaster.tact";
import "../imports/tonion/JettonWallet.tact";

contract MyJettonWallet with JettonWallet, Deployable {
    balance: Int as coins = 0;
    owner: Address;
    jetton_master: Address;

    init(owner: Address, jetton_master: Address) {
        self.owner = owner;
        self.jetton_master = jetton_master;
    }

    override inline fun calculate_jetton_wallet_init(owner_address: Address): StateInit {
        return initOf MyJettonWallet(owner_address, self.jetton_master);
    }
}
```
<br>

### implementation
actually you can find implementation for the traits or TEPs in mock [contracts/mock](./contracts/mocks/) directory

<br>

### Tonion-CLI

We are working on a solution to use `npm` to install Tonion Contracts and import them directly into your contracts without copying the files manually.
Additionally, we are exploring potential changes in Tact to support importing directly from GitHub or similar platforms.

## Traits

```plaintext
┌ contracts/traits
│
├── access
│   │
│   ├── OwnableTransferable2Step.tact ✅
│   │
│   └── AccessControl.tact ✅
│
├── utils
│   │
│   └── Counter.tact ✅
│   
├── payments
│   │
│   └── PaymentSplitter.tact ✅
│   
└── tokens
    │
    ├── jetton
    │   │
    │   ├── JettonMaster.tact ✅
    │   ├── JettonWallet.tact ✅
    │   │
    │   └── extensions
    │       │
    │       ├── MaxSupply.tact ✅
    │       │
    │       └── Approveable.tact ❓
    │
    │
    └── NFT
        │
        ├── NFTCollection.tact ⏳
        ├── NFTItem.tact ⏳
        │
        └── extensions
            │
            ├── Editable.tact ⏳
            │
            ├── MaxSupply.tact ⏳
            │
            └── Royalty.tact ⏳

```

## Scripts

-   **Build All Contracts**: Compiles all the contracts in the library.

    ```sh
    npm run build:all
    ```

-   **Run Tests**: Executes the test suite using Jest.
    ```sh
    npm test
    ```

## Project Structure

```plaintext
┌── contracts
│   │
│   ├── traits
│   │   │
│   │   └── (trait categories)
│   │           │
│   │           └── (trait sub-categories)
│   │               │
│   │               └── (trait files)
│   ├── mocks
│   │   │
│   │   └── (mock categories)
│   │           │
│   │           └── (mock sub-categories)
│   │               │
│   │               └── (mock files)
├── tests
│   │
│   ├── (test categories)
│   │       │
│   │       └── (test files)
│   │
│   └── main.spec.ts
│
├── wrappers
│   │
│   └──(wrapper file)
│
├── package.json
│
└── README.md
```

## Contributing

We welcome contributions from the community! If you'd like to contribute, please follow these steps:

1. Fork the repository.
2. Add a feature or fix a bug
3. Open a pull request.

## Contributors

<!-- readme: contributors -start -->
<table>
	<tbody>
		<tr>
            <td align="center">
                <a href="https://github.com/ZigBalthazar">
                    <img src="https://avatars.githubusercontent.com/u/42387185?v=4" width="50;" alt="ZigBalthazar"/>
                    <br />
                    <sub><b>Zig Blathazar</b></sub>
                </a>
            </td>
            <td align="center">
                <a href="https://github.com/kehiy">
                    <img src="https://avatars.githubusercontent.com/u/89645414?v=4" width="50;" alt="kehiy"/>
                    <br />
                    <sub><b>Kay</b></sub>
                </a>
            </td>
            <td align="center">
                <a href="https://github.com/olumo-oke">
                    <img src="https://avatars.githubusercontent.com/u/173970179?v=4" width="50;" alt="olumo-oke"/>
                    <br />
                    <sub><b>olumo-oke</b></sub>
                </a>
            </td>
            <td align="center">
                <a href="https://github.com/satyasai69">
                    <img src="https://avatars.githubusercontent.com/u/62896328?v=4" width="50;" alt="satyasai69"/>
                    <br />
                    <sub><b>satya sai</b></sub>
                </a>
            </td>
            <td align="center">
                <a href="https://github.com/seniorGarin">
                    <img src="https://avatars.githubusercontent.com/u/72135452?v=4" width="50;" alt="seniorGarin"/>
                    <br />
                    <sub><b>seniorGarin</b></sub>
                </a>
            </td>
		</tr>
	<tbody>
</table>
<!-- readme: contributors -end -->

## License

This project is licensed under the MIT License - see the [MIT License](LICENSE) file for details.
