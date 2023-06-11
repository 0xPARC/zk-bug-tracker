# ZK Bug Tracker
A community-maintained collection of bugs, vulnerabilities, and exploits in apps using ZK crypto.

There are two sections - *Bugs in the Wild* and *Common Vulnerabilities*.
The *Bugs in the Wild section* is a list of actual bugs found in zk related codebases.
The *Common Vulnerabilities* section outlines the common categories of zk related bugs that have been found.
These lists can be used as a reference for developers, auditors, and security tool makers.

#### Contributing
If you would like to add a "bug in the wild" or a "common vulnerability", there are two ways to do so:
1. Create a PR, filling in all of the necessary details yourself
2. Create an issue with a link or description of the bug or common vulnerability. The repo maintainers will then fill out the relevant details in a PR.

# Table of Contents
#### [Bugs in the Wild](#bugs-in-the-wild-header)
 1. [Dark Forest v0.3: Missing Bit Length Check](#dark-forest-1)
 2. [BigInt: Missing Bit Length Check](#bigint-1)
 3. [Circom-Pairing: Missing Output Check Constraint](#circom-pairing-1)
 4. [Semaphore: Missing Smart Contract Range Check](#semaphore-1)
 5. [Zk-Kit: Missing Smart Contract Range Check](#zk-kit-1)
 6. [Aztec 2.0: Missing Bit Length Check / Nondeterministic Nullifier](#aztec-1)
 7. [Aztec Plonk Verifier: 0 Bug](#aztec-2)
 8. [0xPARC StealthDrop: Nondeterministic Nullifier](#stealthdrop-1)
 9. [a16z ZkDrops: Missing Nullifier Range Check](#zkdrops-1)
 10. [MACI 1.0: Under-constrained Circuit](#maci-1)
 11. [Bulletproofs Paper: Frozen Heart](#bulletproofs-1)
 12. [PlonK: Frozen Heart](#plonk-1)
 13. [Zcash: Trusted Setup Leak](#zcash-1)
 14. [MiMC Hash: Assigned but not Constrained](#mimc-1)
 15. [PSE & Scroll zkEVM: Missing Overflow Constraint](#zkevm-1)
 16. [PSE & Scroll zkEVM: Missing Constraint](#zkevm-2)
 17. [Dusk Network: Missing Blinding Factors](#dusk-1)
 18. [EY Nightfall: Missing Nullifier Range Check](#nightfall-1)
 19. [Summa: Unconstrained Constants Assignemnt](#summa-1)


#### [Common Vulnerabilities](#common-vulnerabilities-header)
 1. [Under-constrained Circuits](#under-constrained-circuits)
 2. [Nondeterministic Circuits](#nondeterministic-circuits)
 3. [Arithmetic Over/Under Flows](#arithmetic-over-under-flows)
 4. [Mismatching Bit Lengths](#mismatching-bit-lengths)
 5. [Unused Public Inputs Optimized Out](#unused-pub-inputs)
 6. [Frozen Heart: Forging of Zero Knowledge Proofs](#frozen-heart)
 7. [Trusted Setup Leak](#trusted-setup-leak)
 8. [Assigned but not Constrained](#assigned-not-constrained)

#### [Zk Security Resources](#zk-security-resources-header)


# <a name="bugs-in-the-wild-header">Bugs in the Wild</a>

## <a name="dark-forest-1">1. Dark Forest v0.3: Missing Bit Length Check</a>

**Summary**

Related Vulnerabilities: 1. Under-constrained Circuits, 2. Nondeterministic Circuits, 3. Arithmetic Over/Under Flows, 4. Mismatching Bit Lengths

Identified By: [Daira Hopwood](https://github.com/daira)

A *RangeProof* circuit was used to prevent overflows. However, it used the CircomLib *[LessThan](https://github.com/iden3/circomlib/blob/master/circuits/comparators.circom#L89)* circuit to ensure this, which expects a maximum number of bits for each input. The inputs did not have any constraints on the number of bits, so an attacker could use large numbers to achieve a successful *RangeProof* even though the number was out of range.

**Background**

Dark Forest, a fully decentralized and real time strategy game, had a missing bit length check from its early circuits. In order to prevent underflows their circuit included a *RangeProof* template to ensure that an input is within bounds to prevent an overflow.

```jsx
// From darkforest-v0.3/circuits/range_proof/circuit.circom
template RangeProof(bits, max_abs_value) {
    signal input in;

    component lowerBound = LessThan(bits);
    component upperBound = LessThan(bits);

    lowerBound.in[0] <== max_abs_value + in;
    lowerBound.in[1] <== 0;
    lowerBound.out === 0

    upperBound.in[0] <== 2 * max_abs_value;
    upperBound.in[1] <== max_abs_value + in;
    upperBound.out === 0
}
```

 The *LessThan* template compares two inputs, and outputs 1 if the first input is less than the second input. In the *RangeProof* circuit, the *LessThan* circuit is essentially used as a GreaterEqThan, requiring that the output is 0. The *LessThan* template takes in the max number of bits for both inputs as a parameter, but does not actually check this constraint.

```jsx
// From circomlib/circuits/comparators.circom
template LessThan(n) {
    assert(n <= 252);
    signal input in[2];
    signal output out;

    component n2b = Num2Bits(n+1);

    n2b.in <== in[0]+ (1<<n) - in[1];

    out <== 1-n2b.out[n];
}
```

**The Vulnerability**

Therefore, in the *RangeProof* example the *LessThan* circuit is used with an expected maximum number of bits, but the inputs *max_abs_value* and *in* are never constrained to that number. An attacker could input *max_abs_value* and *in* values that contain more bits than the expected max. Since *LessThan* is expecting the two inputs to have a maximum number of bits, it may output an incorrect result. An attacker would be able to satisfy the *RangeProof* even though the input is out of range.

**The Fix**

In order to prevent this attack, a check was needed on the number of bits of *max_abs_value* and *in*. They must be constrained to *bits *****(the template input parameter) number of bits. The following is the implemented fix in production:

```jsx
// From darkforest-eth/circuits/range_proof/circuit.circom

// NB: RangeProof is inclusive.
// input: field element, whose abs is claimed to be <= than max_abs_value
// output: none
// also checks that both max and abs(in) are expressible in `bits` bits
template RangeProof(bits) {
    signal input in;
    signal input max_abs_value;

    /* check that both max and abs(in) are expressible in `bits` bits  */
    component n2b1 = Num2Bits(bits+1);
    n2b1.in <== in + (1 << bits);
    component n2b2 = Num2Bits(bits);
    n2b2.in <== max_abs_value;

    /* check that in + max is between 0 and 2*max */
    component lowerBound = LessThan(bits+1);
    component upperBound = LessThan(bits+1);

    lowerBound.in[0] <== max_abs_value + in;
    lowerBound.in[1] <== 0;
    lowerBound.out === 0

    upperBound.in[0] <== 2 * max_abs_value;
    upperBound.in[1] <== max_abs_value + in;
    upperBound.out === 0
}
```

**References:**

1. [ZKPs for Engineers: A look at the Dark Forest ZKPs](https://blog.zkga.me/df-init-circuit) (See the “Bonus 1: Range Proofs” section)
2. [Commit of the Fix](https://github.com/darkforest-eth/circuits/commit/1b5c8440a487614d4a3e6ed523df0aee71a05b6e#diff-440e6bdf86d42398f40d29b9df0b9e6992c6859194d2a7f3c8c68fb46d0f2040)

## <a name="bigint-1">2. BigInt: Missing Bit Length Check</a>

**Summary**

Related Vulnerabilities: 1. Under-constrained Circuits, 2. Nondeterministic Circuits, 3. Arithmetic Over/Under Flows, 4. Mismatching Bit Lengths

Identified By: [Andrew He](https://github.com/ecnerwala) and [Veridise Team](https://veridise.com/) independently

The BigMod circuit, used for the modulo operation on big integers, was missing a bit length check on the output remainder. This constraint needs to be added to prevent an attacker from using an unexpectedly large remainder value. This can break a protocol in various ways, depending on how they use this circuit.

**Background**

The BigInt circuits are used to perform arithmetic on integers larger than the SNARK scalar field order. BigMod is the circuit responsible for performing the modulo operation on these large integers. BigMod takes inputs *a* and *b*, and outputs the quotient and remainder of *a % b*. The circuit uses a helper function, *long_division*, to calculate the quotient and remainder. However, functions can’t add constraints, so the BigMod circuit must add constraints to ensure that the quotient and remainder are correct.

Additionally, the BigInt circuits store big integers in two formats: proper representation and signed overflow representation. Proper representation does not allow for integers to be negative whereas the signed overflow representation does. Due to the representation style, the negative signed overflow numbers may have more bits than the proper representation style.

**The Vulnerability**

Two important constraints are ensuring that both the quotient and the remainder are the proper number of bits. There was a bit length check on the quotient, however there was no check for the remainder:

```jsx
// From circom-ecdsa/circuits/bigint.circom before the fix

// Long division helper function. Outputs the quotient and remainder
var longdiv[2][100] = long_div(n, k, k, a, b);
for (var i = 0; i < k; i++) {
    div[i] <-- longdiv[0][i]; // Quotient
    mod[i] <-- longdiv[1][i]; // Remainder
}
div[k] <-- longdiv[0][k];

// Range check for the quotient
component range_checks[k + 1];
for (var i = 0; i <= k; i++) {
    range_checks[i] = Num2Bits(n);
    range_checks[i].in <== div[i];
}
```

Without a bit length constraint on the remainder, the output of this circuit was not guaranteed to be in proper representation. Only the quotient, *div[]*, was constrained to *n* bits per register in the array. The remainder array, *mod[]*, was not constrained to *n* bits. Therefore any consumers of this circuit are not guaranteed to have the remainder be accurate and as expected.

**The Fix**

In order to ensure that the remainder doesn’t contain too many bits and proceed to cause unexpected behavior from there, a bit length constraint must be added. The circuit was changed to incorporate this fix:

```jsx
// From circom-ecdsa/circuits/bigint.circom after the fix

var longdiv[2][100] = long_div(n, k, k, a, b);
for (var i = 0; i < k; i++) {
    div[i] <-- longdiv[0][i];
    mod[i] <-- longdiv[1][i];
}
div[k] <-- longdiv[0][k];

component div_range_checks[k + 1];
for (var i = 0; i <= k; i++) {
    div_range_checks[i] = Num2Bits(n);
    div_range_checks[i].in <== div[i];
}

// The new bit length check on the remainder
component mod_range_checks[k];
for (var i = 0; i < k; i++) {
    mod_range_checks[i] = Num2Bits(n);
    mod_range_checks[i].in <== mod[i];
}
```

**References**

1. [Commit of the Fix](https://github.com/0xPARC/circom-ecdsa/pull/10)
2. [More info on bigint representation](https://hackmd.io/hIfysDw4TtC_6RR4gzdjBw?view)

## <a name="circom-pairing-1">3. Circom-Pairing: Missing Output Check Constraint</a>

**Summary**

Related Vulnerabilities: 1. Under-constrained Circuits, 2. Nondeterministic Circuits, 4. Mismatching Bit Lengths

Identified By: [Veridise Team](https://veridise.com/)

The Circom-Pairing circuits, written in circom, are used for the [Succinct Labs'](https://succinct.xyz/) bridge that is based on cryptographic protocols. However, the circuits were missing a constraint to ensure proper range checks.

**Background**

The Circom-Pairing circuit needs to use integers larger than the prime field (254 bits), so it uses the circom big-int library. Therefore, numbers are represented as `k`-length arrays of `n`-bit numbers to represent a much larger number. Even though Circom-Pairing uses very large numbers, there is still a max range of expected numbers to be used. To ensure that numbers are constrained to the expected max range, the following circuit is often used:

```jsx
template BigLessThan(n, k){
  signal input a[k];
  signal input b[k];
  signal output out;
  ...
}
```

The output of this circuit will be `1` if `a < b`, and `0` otherwise.

**The Vulnerability**

The vulnerability arose in the `CoreVerifyPubkeyG1` circuit:

```jsx
template CoreVerifyPubkeyG1(n, k){
  ...
  var q[50] = get_BLS12_381_prime(n, k);

  component lt[10];
  // check all len k input arrays are correctly formatted bigints < q (BigLessThan calls Num2Bits)
  for(var i=0; i<10; i++){
    lt[i] = BigLessThan(n, k);
    for(var idx=0; idx<k; idx++)
      lt[i].b[idx] <== q[idx];
  }
  for(var idx=0; idx<k; idx++){
    lt[0].a[idx] <== pubkey[0][idx];
    lt[1].a[idx] <== pubkey[1][idx];
    ... // Initializing parameters for rest of the inputs
}
```
The `BigLessThan` circuit is used to constrain `pubkey < q` to ensure that the pubkey values are correctly formatted bigints. However, the rest of the circuit never actually checks the output of these `BigLessThan` circuits. So, even if a proof has `pubkey >= q` and `BigLessThan` outputs `0`, the proof will successfully be verified. This could cause unexpected behavior as the cryptographic protocol depends on these numbers being within the expected range.

**The Fix**

The fix required a constraint on all of the outputs of the `BigLessThan` circuits to ensure that each one had an output of `1`. The following snippet was added to fix this:

```jsx
var r = 0;
for(var i=0; i<10; i++){
    r += lt[i].out;
}
r === 10;
```

Once this was added, each `BigLessThan` circuit was then constrained to equal `1`. Now, the `pubkey` inputs can be trusted to be in the expected range.

**References**

1. [Veridise Explainer Article](https://medium.com/veridise/circom-pairing-a-million-dollar-zk-bug-caught-early-c5624b278f25)
2. [Commit of the Fix](https://github.com/yi-sun/circom-pairing/pull/21/commits/c686f0011f8d18e0c11bd87e0a109e9478eb9e61)

## <a name="semaphore-1">4. Semaphore: Missing Smart Contract Range Check</a>

**Summary**

Related Vulnerabilities: 3. Arithmetic Over/Under Flows

Identified By: [PSE Security Team](https://twitter.com/PrivacyScaling)

The Semaphore smart contracts performed range checks in some places but not others. The range checks were to ensure that all public inputs were less than the snark scalar field order. However, these checks weren’t enforced in all the necessary places. This could cause new Semaphore group owners to unknowingly create a group that will always fail verification.

**Background**

Semaphore is a dapp built on Ethereum that allows users to prove their membership of a group and send signals such as votes or endorsements without revealing their original identity. Essentially, trusted coordinators create a group (with a group Id) and add members via the smart contracts. Members can then submit zero knowledge proofs to the coordinator that prove their membership of the group and optionally contain a signal with it.

**The** **Vulnerability**

Since the Solidity *uint256* type can hold numbers larger than the snark scalar field order, it is important to be weary of overflows. In order to prevent unwanted overflows, the Semaphore verifier smart contract automatically fails if a public input is greater than the snark scalar field order:

```jsx
// From Semaphore/contracts/base/Verifier.sol (outdated)
require(input[i] < snark_scalar_field, "verifier-gte-snark-scalar-field");
```

When a coordinator creates a new group, they can input any valid *uint256* value as the id. This is a problem since the id is a public input for the zk proof. If the id is greater than the snark scalar field order, the verifier will always revert and the group isn’t operable.

**The Fix**

To prevent an inoperable group from being created, a check on the group Id is needed. This check needs to ensure that the new group id will be less than the snark scalar field order:

```jsx
// From Semaphore/contracts/base/SemaphoreGroups.sol
function _createGroup(
    uint256 groupId,
    uint8 depth,
    uint256 zeroValue
  ) internal virtual {
		// The Fix is the following require statement:
    require(groupId < SNARK_SCALAR_FIELD, "SemaphoreGroups: group id must be < SNARK_SCALAR_FIELD");
    require(getDepth(groupId) == 0, "SemaphoreGroups: group already exists");

    groups[groupId].init(depth, zeroValue);
    emit GroupCreated(groupId, depth, zeroValue);
  }
```

**References**

1. [Reported Github Issue](https://github.com/semaphore-protocol/semaphore/issues/90)
2. [Commit of the Fix](https://github.com/semaphore-protocol/semaphore/pull/91)

## <a name="zk-kit-1">5. Zk-Kit: Missing Smart Contract Range Check</a>

**Summary**

Related Vulnerabilities: 3. Arithmetic Over/Under Flows

Identified By: [PSE Security Team](https://twitter.com/PrivacyScaling)

The Zk-Kit smart contracts implement an incremental merkle tree. The intent is for this merkle tree to be involved with zk proofs, so all values must be less than the snark scalar field order in order to prevent overflows.

**Background**

Semaphore is the first consumer of the Zk-Kit merkle tree implementation. When members sign up via the Semaphore smart contracts, they use an *identityCommitment* that is stored in the on-chain Zk-Kit merkle tree. The zero knowledge proof will then prove that they have a valid commitment in the tree.

**The** **Vulnerability**

When initializing the merkle tree, you must specify a value for the zero leaf:

```jsx
// From zk-kit/incremental-binary-tree.sol/contracts/IncrementalBinaryTree.sol
// before the fix
function init(
    IncrementalTreeData storage self,
    uint8 depth,
    uint256 zero
  ) public {
    require(depth > 0 && depth <= MAX_DEPTH, "IncrementalBinaryTree: tree depth must be between 1 and 32");

    self.depth = depth;

    for (uint8 i = 0; i < depth; i++) {
      self.zeroes[i] = zero;
      zero = PoseidonT3.poseidon([zero, zero]);
    }

    self.root = zero;
  }
```

Since the Solidity *uint256* allows for numbers greater than the snark scalar field order, a user could unknowingly initialize a merkle tree with the zero leaf value greater than the snark scalar field order. This will also directly cause overflows if the zero leaf is part of a merkle tree inclusion proof needed for a zk proof.

**The Fix**

During initialization, it must be enforced that the given zero leaf value is less than the snark scalar field order. To enforce this, the following require statement was added to the *init* function:

```jsx
// From zk-kit/incremental-binary-tree.sol/contracts/IncrementalBinaryTree.sol
// after the fix
require(zero < SNARK_SCALAR_FIELD, "IncrementalBinaryTree: leaf must be < SNARK_SCALAR_FIELD");
```

**References**

1. [Reported Github Issue](https://github.com/privacy-scaling-explorations/zk-kit/issues/23)
2. [Commit of the Fix](https://github.com/privacy-scaling-explorations/zk-kit/pull/24)

## <a name="aztec-1">6. Aztec 2.0: Missing Bit Length Check / Nondeterministic Nullifier</a>

**Summary**

Related Vulnerabilities: 1. Under-constrained Circuits, 2. Nondeterministic Circuits, 4. Mismatching Bit Lengths

Identified By: [Aztec Team](https://aztec.network/)

Funds in the Aztec protocol are held in what are called “note commitments”. Once a note commitment is spent, it should not be possible to spend it again. However, due to a missing bit length check, an attacker could spend a single note commitment multiple times.

**Background**

Whenever a new note commitment is created, it is stored in a merkle tree on-chain. In order to prevent double spending of a single note commitment, a nullifier is posted on-chain after the note is spent. If the nullifier was already present on-chain, then the note cannot be spent.

**The Vulnerability**

The nullifier generation process should be deterministic so that the same nullifier is generated for the same note commitment every time. However, due to a missing bit length check, the process was not deterministic. The nullifier was generated based on the note commitment index in the merkle tree. The code assumed the index to be a 32 bit number, but there was no constraint enforcing this check.

An attacker could use a number larger than 32 bits for the note index, as long as the first 32 bits matched the correct index. Since they can generate many unique numbers that have the same first 32 bits, a different nullifier will be created for each number. This allows them to spend the same note commitment multiple times.

**The Fix**

A bit length check was needed on the given note commitment index to enforce that it was at max 32 bits.

**References**

1. [Aztec Bug Disclosure](https://hackmd.io/@aztec-network/disclosure-of-recent-vulnerabilities)

## <a name="aztec-2">7. Aztec Plonk Verifier: 0 Bug</a>

**Summary**

Related Vulnerabilities: Missing Curve Point Checks

Identified By: [Nguyen Thoi Minh Quan](https://github.com/cryptosubtlety)

The Aztec Plonk verifier, written in C++, accepts proofs containing multiple elements as per the Plonk protocol. However, by manually setting two of the elements to 0, the verifier will automatically accept that proof regardless of the other elements. This allows an attacker to successfully forge a proof.

**Background**

The full description of this bug is quite math heavy and dives deep into the Plonk protocol. The finder of this bug, Nguyen Thoi Minh Quan, has a great detailed description of the bug [here](https://github.com/cryptosubtlety/00/blob/main/00.pdf).

Elliptic curves have what is known as a point at infinity. Let `O = point at infinity` and `P` be any point on the curve. Then `O + P = P`. When implementing a cryptographic protocol in code, there are different ways to express the point at inifinity. For example, sometimes the number `0` is considered the point at infinity, but other times `0` is considered as the point `(0, 0)`, which is not the point at infinity. This will be important later.

Plonk proofs require a group of elements and curve points, and then will check whether these elements and points satisfy certain equations. One of the main equations to check is an elliptic curve pairing. The curve points that are of importance for this bug are [W<sub>z</sub>]<sub>1</sub> and [W<sub>zw</sub>]<sub>1</sub>.

**The Vulnerability**

When [W<sub>z</sub>]<sub>1</sub> and [W<sub>zw</sub>]<sub>1</sub> are checked in the verifier code, a value of `0` is recognized as not on the elliptic curve, but the code does not fail immediately. The verifier continues on and later recognizes the `0` value as the point at infinity. This causes the pairing equation to be satisfied, and therefore the proof is successfully verified.

**The Fix**

The verifier was missing checks at a few different spots in the code. Just one of these checks would stop the 0 bug from working. These checks are explained in more detail in the finder's description. A simple to understand fix would be to agree on a consistent representation of the point at infinity. If `0` was consistently decided as not the point at infinity, then this bug would not work.

This bug is a good example of how implementing a secure cryptographic protocol can become insecure very easily. If one follows the Plonk paper exactly, this bug is not possible. This is a good reminder to test a protocol with inputs that theoretically would never work, as this finder did.

**References**

1. [Nguyen Thoi Minh Quan's Description](https://github.com/cryptosubtlety/00/blob/main/00.pdf)


## <a name="stealthdrop-1">8. 0xPARC StealthDrop: Nondeterministic Nullifier</a>

**Summary**

Related Vulnerabilities: 1. Under-constrained Circuits, 2. Nondeterministic Circuits

Identified By: [botdad](https://twitter.com/0xB07DAD)

StealthDrop requires users post a nullifier on-chain when they claim an airdrop. If they try to claim the airdrop twice, the second claim will fail. However, ECDSA signatures were used as the nullifier and these signatures are nondeterministic. Therefore different signatures were valid nullifiers for a single claim and users could claim an airdrop multiple times by sending the different valid signatures.

**Background**

In order to claim an airdrop, users must post a nullifier on-chain. If the nullifier is already present on-chain, the airdrop will fail. The nullifier is supposed to be computed in a deterministic way such that given the same input parameters (the user’s claim in this case), the output nullifier will always be the same. The initial nullifier generation process required users to sign a particular message with their ECDSA private key. The resultant signature is the nullifier that they need to post on-chain when claiming an airdrop.

**The Vulnerability**

ECDSA signature validation is nondeterministic - a user can use a private key to sign a message in multiple ways that will all pass signature verification. When users create the SNARK to claim an airdrop, they use the nullifier as a public input. The SNARK circuit enforces that the nullifier is a valid signature. Since the users can create multiple valid signatures with the same key and message, they can create multiple proofs with different nullifiers. This allows them to submit these separate proofs and claim an airdrop multiple times.

**The Fix**

Instead of only constraining signature validation in the SNARK circuit, constraints must also be added on the signature creation process so that the signatures are deterministic. This was originally left out because in order to constrain the signature creation process, the private key is needed as a private input. The StealthDrop team wanted to avoid involving the private key directly. However, due to the vulnerability described, the private key is needed in the circuit to make the signature creation process deterministic.

**References**

1. [0xPARC Twitter Thread Explanation](https://twitter.com/0xPARC/status/1493705025385906179)

## <a name="zkdrops-1">9. a16z ZkDrops: Missing Nullifier Range Check</a>

**Summary**

Related Vulnerabilities: 1. Under-constrained Circuits, 2. Nondeterministic Circuits, 3. Arithmetic Over/Under Flows

Identified By: [Kobi Gurkan](https://github.com/kobigurk)

ZkDrops is very similar to the 0xPARC StealthDrop (related bug just above). ZkDrops requires that users post a nullifier on-chain when they claim an airdrop. If they try to claim the airdrop twice, the second claim will fail because the nullifier has already been seen by the smart contract. However, since the EVM allows numbers (256 bits) larger than the snark scalar field order, arithmetic overflows allowed users to submit different nullifiers for the same airdrop claim. This made it possible for a user to claim a single airdrop multiple times.

**Background**

In order to claim an airdrop, users must post a nullifier on-chain. If the nullifier is already present on-chain, the airdrop will fail. The nullifier is supposed to be computed in a deterministic way such that given the same input parameters (the user’s claim in this case), the output nullifier will always be the same. The nullifier is stored on-chain as a 256 bit unsigned integer. 

Since the SNARK scalar field is 254 bits, a nullifier that is `> 254 bits` will be reduced modulo the SNARK field during the proof generation process. For example, let `p = SNARK scalar field order`. Then any number `x` in the proof generation process will be reduced to `x % p`. So `p + 1` will be reduced to `1`.

**The Vulnerability**

The smart contract that checked whether a nullifier has been seen before or not, did not verify whether the nullifier was within the SNARK scalar field. So, if a user has a nullifier `x >= p`, then they could use both `x and x % p` as separate nullifiers. These both will be evaluated to `x % p` within the circuit, so both would generate a successful proof. When the user first claims an airdrop with the `x` nullifier, `x` hasn't been seen before so it is successful. Then when the user claims the same airdrop with `x % p`, that value hasn't been seen by the contract before either, so it is successful as well. The user has now claimed the airdrop twice.

**The Fix**

The fix to this issue is to add a range check in the smart contract. This range check should ensure that all nullifiers are within the SNARK scalar field so that no duplicate nullifiers satisfy the circuit. The following function to claim an airdrop:

```jsx
/// @notice verifies the proof, collects the airdrop if valid, and prevents this proof from working again.
function collectAirdrop(bytes calldata proof, bytes32 nullifierHash) public {
	require(!nullifierSpent[nullifierHash], "Airdrop already redeemed");

	uint[] memory pubSignals = new uint[](3);
	pubSignals[0] = uint256(root);
	pubSignals[1] = uint256(nullifierHash);
	pubSignals[2] = uint256(uint160(msg.sender));
	require(verifier.verifyProof(proof, pubSignals), "Proof verification failed");
	nullifierSpent[nullifierHash] = true;
	airdropToken.transfer(msg.sender, amountPerRedemption);
}
```

Was fixed by adding this range check:

```jsx
require(uint256(nullifierHash) < SNARK_FIELD ,"Nullifier is not within the field");
```

**References**

1. [Github PR](https://github.com/a16z/zkdrops/pull/2)

## <a name="maci-1">10. MACI 1.0: Under-constrained Circuit</a>

**Summary**

Related Vulnerabilities: 1. Under-constrained Circuits, 2. Nondeterministic Circuits

Identified By: [PSE Security Team](https://twitter.com/PrivacyScaling)

MACI is a dapp for collusion resistant voting on-chain. Encrypted votes are sent on-chain and a trusted coordinator decrypts the votes off-chain, creates a SNARK proving the results, and then verifies the proof on-chain. The SNARK circuit logic aims to prevent the coordinator from censoring any valid vote - the proof should fail verification if the coordinator attempts to do so. However, a missing logic constraint in the circuit allows the coordinator to shuffle some votes and render targeted votes as invalid. This effectively allows the coordinator to censor any vote they choose.

**Background**

In order to be able to vote, a user must sign up to the MACI smart contract with a public key. These public keys are stored on-chain in a merkle tree. Users need to know the private key of these public keys in order to vote. When users cast a vote, they encrypt their vote and post it on-chain. Users can override their previous vote by sending a new one. MACI has certain rules for a vote to be considered valid, and the newest valid vote will take precedence over all other votes. The vote includes a *stateIndex* which is the position of the associated public key in the merkle tree. If the voter doesn’t know the private key of the public key at *stateIndex*, the vote will be considered invalid. When the coordinator processes all of the votes, they must only count the newest valid vote for each user. The SNARK circuit logic is designed to constrain the coordinator to doing exactly that. Therefore, if the circuit works as intended, the coordinator is not able to create a proof of voting results that include invalid votes or exclude valid votes. It is censorship resistant.

The circuit *ProcessMessages.circom* takes as input an array of user public keys -*currentStateLeaves[] -* along with the votes to process - *msgs[]*. The vote actions in the *msgs* array are processed on the public keys in the *currentStateLeaves* array:

```jsx
// The state leaves upon which messages are applied.
// Pseudocode
transform(currentStateLeaf[4], msgs[4]) ==> newStateLeaf4
transform(currentStateLeaf[3], msgs[3]) ==> newStateLeaf3
transform(currentStateLeaf[2], msgs[2]) ==> newStateLeaf2
transform(currentStateLeaf[1], msgs[1]) ==> newStateLeaf1
transform(currentStateLeaf[0], msgs[0]) ==> newStateLeaf0
```

In MACI, a valid vote message can be used to change a user’s public key. From that point on, user’s can only use the new public key to update/create votes. The *transform* function will output the updated state leaf with the new public key if it was changed.

**The Vulnerability**

The *currentStateLeaf* array is ordered by the coordinator. Therefore, the coordinator effectively has control over which public key a new vote message is applied to. Therefore, they can choose to apply a vote message from one user, to another user’s public key. This will cause that vote message to be considered invalid since it doesn’t match the public key.

There is a constraint ensuring that a message’s *stateIndex* matches the public key it was applied on, but this constraint only marks a vote message as invalid if so. Before the *stateIndex* is checked, the circuit checks other cases where the message may be invalid, such as if the public key matches this new vote message. If it gets marked as invalid, the *stateIndex* check won’t make any changes. This circuit is under-constrained.

If a malicious coordinator wants to censor *msgs[3]* (the 4th voting message), then they will set *currentStateLeaf[3]* to the 0 leaf. Then, *msgs[3*] will be marked as invalid since the public key doesn’t match. The check that *currentStateLeaf[3].index === msgs[3].stateIndex* is avoided since the message is already invalid. The coordinator has effectively censored *msgs[3]*.

**The Fix**

The main issue that needs to be fixed is constraining voting messages to the intended public keys. The circuit is quite complicated so other changes needed to be made, but the most significant change was adding the following check before marking a vote message as invalid:

```jsx
// Pseudo code
currentStateLeaf[i].index <== msgs[i].stateIndex
```

This check ensures that the vote message is applied to the intended public key (state leaf) before marking any message as invalid. Therefore, a coordinator can no longer mismatch vote messages to unintended public keys and purposefully mark them as invalid.

**References**

1. [Issue on Github](https://github.com/privacy-scaling-explorations/maci/issues/320)

## <a name="bulletproofs-1">11. Bulletproofs Paper: Frozen Heart</a>

**Summary**

Related Vulnerabilities: 6. Frozen Heart

Identified By: [TrailOfBits Team](https://www.trailofbits.com/)

The bulletproof paper, which outlines the bulletproof zero knowledge proof protocol, outlines how to use the Fiat-Shamir transformation to make the proof non-interactive. However, their recommended implementation of the Fiat-Shamir transformation left out a crucial component. This missing component in the non-interactive version of the protocol allowed malicious provers to forge proofs.

**Background**

Many zero knowledge proof protocols are first designed in an interactive way where the prover and verifier must communicate with each other for multiple rounds in order for the proof to be created and subsequently verified. This often takes the form of:

1. The prover creates a random value known as the commitment
2. The verifier replies with a random value known as the challenge
3. The prover uses the commitment, challenge, and their secret data to create a proof

For the proof to be secure, the verifier’s challenge must be entirely unpredictable and uncontrollable by the prover.

The Fiat-Shamir transformation allows the zero-knowledge proof protocol to become non-interactive by having the prover compute the challenge instead of the verifier. The prover should have no control in the challenge’s value, so the prover must use a hash of all public values, including the commitments. This way the prover cannot easily manipulate the proof to be accepted for invalid inputs.

Bulletproofs use Pedersen commitments, which are of the form:

```jsx
commitment = (g^v)(h^gamma)
```

Here *g* and *h* are elliptic curve points and *v* is a secret number. The bulletproof is meant to prove that *v* falls within a certain range. Since this commitment is public, it should be included in the Fiat-Shamir transformation used in the protocol.

**The Vulnerability**

The bulletproof paper provided insecure details on how to implement the Fiat-Shamir transformation for the protocol. Their implementation did not include the Pedersen commitment in the Fiat-Shamir transformation. This means that the challenge value is independent of the Pedersen commitment and so the prover can keep trying random values for the commitment until they get a proof that succeeds for *v* outside of the desired range. For more details on how exactly this allows a malicious prover to forge a proof, please see the TrailOfBits’ explanation in the references section.

**The Fix**

In order to prevent this Frozen Heart vulnerability, the Pedersen commitment should be added to the Fiat-Shamir transformation hash. This will make the challenge directly dependent on the commitment and restrict the prover’s freedom when making the proof. The new restriction is enough to prevent the prover from forging proofs.

**References**

1. [TrailOfBits Explanation](https://blog.trailofbits.com/2022/04/15/the-frozen-heart-vulnerability-in-bulletproofs/)

## <a name="plonk-1">12. PlonK: Frozen Heart</a>

**Summary**

Related Vulnerabilities: 6. Frozen Heart

Identified By: [TrailOfBits Team](https://www.trailofbits.com/)

Please see *8. Bulletproofs: Frozen Heart* for a more in-depth background.

Due to some ambiguity in the PlonK paper regarding Fiat-Shamir transformations, a few production implementations did not handle it correctly. The Fiat-Shamir transformation requires all public inputs to be included in the hash. However, some implementations did not properly include all of these public inputs. This allowed malicious provers to forge proofs to different extents, depending on the rest of the implementation details.

**Background**

The PlonK protocol is originally described as an interactive proof protocol between the prover and verifier. However, the paper provides some details on how to make it a non-interactive proof protocol. The paper outlines details on implementing the Fiat-Shamir transformation to make the protocol non-interactive, but it still lacks clarity on what inputs exactly are needed to make it secure.

**The Vulnerability**

Multiple implementations had a frozen heart vulnerability due to their implementation of the Fiat-Shamir transformation. Each implementation had missing public inputs to the hash for the Fiat-Shamir transformation, and thus gave more freedom to the prover when constructing proofs. With this increased freedom, a malicious prover could then forge a proof. The extent of the forgery depends on the rest of the implementation details and so it varied for the different implementations affected by this vulnerability. For more exact details about this vulnerability, please see the TrailOfBits’ explanation in the references section.

**The Fix**

The fix for these vulnerabilities differs for each implementation affected, but it generally includes a fix to the Fiat-Shamir transformation. The fix involves ensuring that all public inputs are included in the hash so that the prover does not have the freedom needed to forge a proof.

**References**

1. [TrailOfBits Explanation](https://blog.trailofbits.com/2022/04/18/the-frozen-heart-vulnerability-in-plonk/)

## <a name="zcash-1">13. Zcash: Trusted Setup Leak</a>

**Summary**

Related Vulnerabilities: 7. Trusted Setup Leak

Identified By: [Zcash Team](https://z.cash/)

The Zcash zero-knowledge proofs are based on a modified version of the Pinocchio protocol. This protocol relies on a trusted setup of parameters based on the Zcash circuit. However, some of the parameters generated as part of this trusted setup allow a malicious prover to forge a proof that creates new Zcash tokens.

**Background**

For zero-knowledge protocols such as Pinocchio and Groth16, a trusted setup is required. The trusted setup is a way to generate the proper parameters needed so that the prover can generate a proof, and the verifier can properly verify it. The trusted setup process usually involves parameters that must be kept secret, otherwise malicious provers can forge proofs. These parameters are known as “toxic waste” and kept private through the use of multi-party computation. Therefore, it’s very important the trusted set-up process generates the correct parameters and keeps the toxic waste hidden.

**The Vulnerability**

The trusted setup for Zcash’s implementation of Pinocchio generated extra parameters that leaked information about the toxic waste. These extra parameters allowed malicious provers to forge proofs that would create Zcash tokens out of nothing. The use of the extra parameters essentially allowed users to counterfeit tokens. However, this vulnerability was never exploited.

**The Fix**

Since the toxic parameters were visible on the trusted setup ceremony document, it was impossible to ensure no one had seen them. The issue was fixed by the Zcash Sapling upgrade which involved a new trusted setup. The new trusted setup was ensured to not release any toxic parameters. Please see the Zcash explanation in the references section for more details on the timeline of events.

**References**

1. [Zcash Explanation](https://electriccoin.co/blog/zcash-counterfeiting-vulnerability-successfully-remediated/)
2. [Pinocchio Protocol](https://eprint.iacr.org/2013/279)
3. [Zcash’s Modified Pinocchio Protocol](https://eprint.iacr.org/2013/879)

## <a name="mimc-1">14. MiMC Hash: Assigned but not Constrained</a>

**Summary**

Related Vulnerabilities: 1. Under-constrained Circuits, 2. Nondeterministic Circuits, 8. Assigned but not Constrained

Identified By: [Kobi Gurkan](https://github.com/kobigurk)

The MiMC hash circuit from the circomlib package had a missing constraint during its computation logic. The circuit was under-constrained and nondeterministic because it didn't properly constrain MiMC inputs to the correct hash output.

**Background**

In circom constraints are created by the following three operators: `<==`, `===`, and `==>`. If other operators are used such as `<--`, `=`, or `-->`, then a constraint will not be added to the R1CS file. These other operators assign numbers or expressions to variables, but do not constrain them. Proper constraints are what is needed for the circuit to be sound.

**The Vulnerability**

During a computation step for this circuit, the `=` operator was used instead of the `<==` operator that was needed to create a constraint. Here is the code before the fix:

```jsx
outs[0] = S[nInputs - 1].xL_out;
```

The `=` operator assigned `S[nInputs - 1].xL_out` to `outs[0]`, but did not actually constrain it. An attacker could then manipulate outs[0] when creating their own proof to manipulate the final output MiMC hash. Essentially, an attacker can change the MiMC hash output for a given set of inputs.

Since this hash function was used in the TornadoCash circuits, this would allow the attacker to fake a merkle root and withdraw someone else's ETH from the contract.

**The Fix**

The fix was simply to change `=` to a constraint operator `<==`.
```jsx
outs[0] <== S[nInputs - 1].xL_out;
```

**References**

1. [TornadoCash Explanation](https://tornado-cash.medium.com/tornado-cash-got-hacked-by-us-b1e012a3c9a8)
2. [Actual Github Fix](https://github.com/iden3/circomlib/pull/22/files)

## <a name="zkevm-1">15. PSE & Scroll zkEVM: Missing Overflow Constraint</a>

**Summary**

Related Vulnerabilities: 1. Under-constrained Circuits, 2. Nondeterministic Circuits, 8. Assigned but not Constrained

Identified By: [PSE Security Team](https://twitter.com/PrivacyScaling)

The PSE & Scroll zkEVM modulo circuit was missing a constraint, which would allow a malicious prover to create a valid proof of a false modulo operation. Since the modulo operation is a basic building block for the zkEVM, the prover could convince the verifier of a wrong state update.

**Background**

The PSE & Scroll zkEVM circuits are programmed using their own fork of [Zcash's Halo2](https://github.com/zcash/halo2). Small components of the large zkEVM circuit can be broken down into what are called gadgets. In this case, the modulo gadget was missing a constraint.

The Modulo gadget is intended to constrain:

```jsx
a mod n = r, if n!=0
r = 0,       if n==0
```

The prover must supply `a, n, r, and k`, where they are all less than `2^256`. The Modulo gadget uses the MulAddWords gadget which constrains:

```jsx
a * b + c == d (modulo 2**256)
```

And the prover must supply `a, b, c, and d`. So the Modulo gadget inputs `k, n, r, a` for `a, b, c, d`. This creates the following constraint:

```jsx
k * n + r == a (modulo 2**256)
```

This constraint is intended to prove that `r = a mod n`. The assignment in the `assign` function calculates this correctly, but the constraints do not enforce it properly.

**The Vulnerability**

The vulnerability arises from the fact that the MulAddWords gadget is done modulo `2^256` and that `k * n + r` can also be greater than `2^256`. This is because even though `k, n, r` are all less than `2^256`, their multiplication and sum can be greater than that. Since the prover can manipulate `k` freely for a given `n, r and a`, the prover can use `k` to overflow the sum and get a successful modulo operation.

For example, let:

```jsx
n = 3
k = 2^255
r = 0
a = 2^255
```

The statement `0 = 2^255mod3` is false. But this statement will prove successfully in the circuit. This is because this is the actual constraint that is checked (which is true in this case):

`3 * 2^255 + 0 = 2^255 (mod 2^256).`

Since the prover can prove these false modulo operations, they can convince the verifier of incorrect state updates that rely on these operations. The modulo operation is a basic building block of the zkEVM, so there are many possible incorrect state updates that a prover can make that will successfully be verified.

**The Fix**

The fix for this issue is to add another constraint forcing `k * n + r` to be less than `2^256` so that no overflows happen. This is enough to avoid the overflow and accurately prove that `r = a mod n` for any `r, a, and n` less than `2^256`.

**References**

1. [Github Issue](https://github.com/privacy-scaling-explorations/zkevm-circuits/issues/996)
2. [Commit of the Fix](https://github.com/privacy-scaling-explorations/zkevm-circuits/pull/999)

## <a name="zkevm-2">16. PSE & Scroll zkEVM: Missing Constraint</a>

Related Vulnerabilities: 1. Under-constrained Circuits, 2. Nondeterministic Circuits, 8. Assigned but not Constrained

Identified By: [PSE Security Team](https://twitter.com/PrivacyScaling)

The PSE & Scroll zkEVM SHL/SHR opcode circuit was missing a constraint, which would allow a malicious prover to create a valid proof of a false shift operation. Since the SHL/SHR opcode is a basic building block for the zkEVM, the prover could convince the verifier of a wrong state update.

**Background**

The SHL/SHR opcode (bit shift left and bit shift right) takes in two inputs from the stack: `x` and `shift`. For SHL it should output `x << shift` and for SHR it should output `x >> shift`. Since `x` and `shift` are on the stack, they each can be any 256 bit value. The calculation of a shift operation involves calculating `2^shift`. Since `shift` can be a very large number, this calculation in a circuit could become very expensive. A to avoid this is recognizing that whenever `shift > 255`, the output to the stack should be `0` both for SHL or SHR. Then make the circuit compute `2^shift` only when `shift <= 255`. This is what the zkEVM SHL/SHR opcode circuit does. Also note that this circuit is shared between both opcodes.

**The Vulnerability**

The opcode circuits take in `shf0` and `shift` as two separate variables, where `shf0` is meant to be the first byte of the `shift` variable. Then, if `shift <= 255`, the circuit calculates `2^shf0`. The `assign_exec_step` function properly assigns these two variables:

```jsx
let shf0 = pop1.to_le_bytes()[0];
...
self.shift.assign(region, offset, Some(pop1.to_le_bytes()))?;
self.shf0.assign(region, offset, Value::known(u64::from(shf0).into()))?;
```

However, the `configure` function, where constraints are created for this opcode, does not properly constrain `shf0` to be the first byte of `shift`. This allows a malicious prover to fork this code and change the `assign_exec_step` function to assign whatever they want to `shf0`. This would allow them to successfully prove `2 << 1 outputs 8` if they assign `shf0 = 2` when it should actually be constrained to output `4`.

**The Fix**

The fix was to add the constraint forcing `shf0` to be the first byte of `shift`. This was done with the following code addition:

```jsx
instruction.constrain_zero(shf0 - FQ(shift.le_bytes[0]))
```

**References**

1. [Github Issue](https://github.com/privacy-scaling-explorations/zkevm-circuits/issues/1124)
2. [The Fix](https://github.com/privacy-scaling-explorations/zkevm-specs/pull/372/files)

## <a name="dusk-1">17. Dusk Network: Missing Blinding Factors</a>

Related Vulnerabilities: Incomplete Protocol Implementation

Identified By: [Dusk Network Team](https://github.com/dusk-network)

The Dusk Network is a privacy-oriented blockchain that relies on zk proofs. In order to achieve certain privacy features, the zk proofs need blinding factors for each proof created. The original Dusk implementation of Plonk was missing some of these blinding factors.

**Background**

ZK SNARKs are useful for both their succinctness and their zero knowledge. The main pieces of the Plonk protocol allows the proofs to be succinct, and it only takes a few small steps to make the protocol zero knowledge as well. Making the protocol zero knowledge means that an attacker cannot look at a proof and then derive the witness used to generate that proof.

In Plonk one of the few steps that makes the protocol zero knowledge is adding blinding factors to the prover polynomials. Essentially, the prover shifts the polynomials by a secret amount while still keeping the proof verficiation successful. These secret shifts prevent others from extracting the witness from the proof.

**The Vulnerability**

Dusk's original Plonk implementation was missing some of these blinding factors. Since Dusk is a privacy-oriented blockchain, many of the inputs to the zk proof need to remain private. However, without blinding factors anyone could potentially extract these "private inputs" from the proof data.

**The Fix**

The fix was to simply add blinding factors to the prover polynomials so that the proof keeps the witness private. The Plonk paper doesn't include much writing on these blinding factors, but still includes them in the final protocol at the end. This is likely because it's quite simple (compared to the rest of the protocol) to include them.

**References**

1. [Github Issue](https://github.com/dusk-network/plonk/issues/650)
2. [Github Fix](https://github.com/dusk-network/plonk/pull/651)
3. [Plonk Paper](https://eprint.iacr.org/2019/953.pdf) - Section 8, first bullet point explains the blinding factors
4. [zkSNARKs in a Nutshell](https://chriseth.github.io/notes/articles/zksnarks/zksnarks.pdf) - Section 4.3 explains blinding factors but for R1CS snarks

## <a name="nightfall-1">18. EY Nightfall: Missing Nullifier Range Check</a>

Related Vulnerabilities: 3. Arithmetic Over/Under flows

Identified By: [BlockHeader](https://github.com/BlockHeader)

EY Nightfall is a set of smart contracts and ZK circuits that allow users to transact ERC20 and ERC-721 tokens privately. The protocol requires that a nullifier be posted on-chain in order to spend private tokens. However, the protocol did not limit the range of the nullifier to the SNARK scalar field size. This allowed users to double spend tokens.

**Background**

In order to prevent double spending of private tokens, a nullifier is posted on-chain after the tokens are spent. If the nullifier was already present on-chain, then the tokens cannot be spent. The nullifier is computed in a deterministic way such that given the same input parameters (specific to the user’s private tokens in this case), the output nullifier will always be the same. The nullifier is stored on-chain as a 256 bit unsigned integer.

The EVM allows numbers up to 256 bits long, whereas the SNARK circuits used for Nightfall only allowed numbers up to around 254 bits long. Since the SNARK scalar field is 254 bits, a nullifier that is `> 254 bits` will be reduced modulo the SNARK field during the proof generation process. For example, let `p = SNARK scalar field order`. Then any number `x` in the proof generation process will be reduced to `x % p`. So `p + 1` will be reduced to 1.

**The Vulnerability**

The smart contract code that stores past used nullifiers did not check to ensure that the nullifier posted was within the SNARK scalar field (`< ~254 bits`). Since the circuit code is responsible for checking whether a given nullifier is correct or not for the tokens being spent, it will only check the reduced 254 bit version of the input nullifier.

For example, let's say a user wants to spend their tokens and the correct nullifier to do so is `n`. Since the correct nullifier is computed in the circuit code, `n` will be `< ~254 bits`. So the user can successfully spend the tokens by posting `n` on-chain as the nullifier. However, they can again post `n + p` on-chain, where `p = snark scalar field size`. Inside the circuit that checks whether `n + p` is correct, it will convert `n + p` to `n + p % p = n`. `n + p` essentially overflows to just `n`. So the circuit checks `n` and is therefore verified as the correct nullifier. On-chain, `n + p` and `n` are treated as two different nullifiers and don't overflow (unless `n + p > 256 bits`), so the nullifiers are stored separately and the tokens are  spent a second time by the same user.

**The Fix**

The fix was to include a range check to ensure that any nullifiers posted on-chain were less than the SNARK scalar field size. This would prevent any overflows inside the circuit. Each token spend now only has one unique nullifier that can be posted on-chain successfully. Here is a snippet of the actual fix, where they ensure the nullifier is correctly range limited:

```jsx
//checks to prevent a ZoKrates overflow attack
require(_inputs[3]<zokratesPrime, "Input too large - possible overflow attack");
require(_inputs[4]<zokratesPrime, "Input too large - possible overflow attack");
```

**References**

1. [Github Issue](https://github.com/EYBlockchain/nightfall/issues/95)
2. [Github Fix](https://github.com/EYBlockchain/nightfall/pull/96)


## <a name="summa-1">19. Summa: Unconstrained Constants Assignemnt </a>

**Summary**

Related Vulnerabilities: 1. Under-constrained Circuits, 8. Assigned but not Constrained

Identified By: [Summa](https://github.com/summa-dev)

The circuit, written in Halo2, makes use of an external `LessThan` gadget that returns 1 if the `lhs` is less than the `rhs`. The logic of the circuit constrains the output to be equal to 1 using an auxiliary value `check`. However, the `check` value is assigned during witness generation. This allows a malicious prover to set `check` to any value, including 0, which would cause the circuit to generate a valid proof for a `lhs` that is greater than the `rhs`.

**Background**

Summa is a zk proof of solvency protocol. As part of the (simplified) logic of the protocol, the prover needs to prove that their `assets_sum` is greater than the `liabilities_sum`. The circuit would use a gadget from [zk-evm](https://github.com/privacy-scaling-explorations/zkevm-circuits/blob/4cfccfa6c3b251284ff61eeb907d548d59206753/gadgets/src/less_than.rs) to perform such less_than verification. The gadget would return 1 if the `lhs` is less than the `rhs`, and 0 otherwise.

**The Vulnerability**

The circuit would have a custom gate to enforce that `check` is equal to `lt` which is the output of the comparison performed by the gadget

```rust
    meta.create_gate(
        "verifies that `check` from current config equal to is_lt from LtChip",
        |meta| {
            let q_enable = meta.query_selector(lt_selector);

            let check = meta.query_advice(col_c, Rotation::cur());

            vec![q_enable * (config.lt_config.is_lt(meta, None) - check)]
        },
    );
```

Later on the circuit would have an assignment function to be called during witness generation to assign the value 1 to check 

```rust
    // set check to be equal to 1
    region.assign_advice(
        || "check",
        self.config.advice[2],
        0,
        || Value::known(Fp::from(1)),
    )?;
```

However, this design erroneusly suppose that any prover would be using the assignment function provided by the library. A malicious prover can simply take the function and modify it to assign a different `Value::known` to `check`, even 0. This would cause the circuit to generate a valid proof for a `lhs` that is greater than the `rhs`.

**The Fix**

To fix the issue, the custom gate has been modified to take a constant expression (and set it to 1!) rather than a value obtained from the advice column (which is the one that can be modified by the prover during witness generation).

```rust
    meta.create_gate("is_lt is 1", |meta| {
        let q_enable = meta.query_selector(lt_selector);

        vec![
            q_enable * (config.lt_config.is_lt(meta, None) - Expression::Constant(Fp::from(1))),
        ]
    });
```

**References:**

1. [Issue](https://github.com/summa-dev/summa-solvency/issues/32)
2. [PR](https://github.com/summa-dev/summa-solvency/pull/40)

# <a name="common-vulnerabilities-header">Common Vulnerabilities</a>

## <a name="under-constrained-circuits">1. Under-constrained Circuits</a>

Under-constrained circuits do not have all of the required constraints necessary to force proof makers to follow the intended rules of the circuit. Many of the other vulnerabilities listed can make a circuit under-constrained, or it can be due to a missing application logic constraint.

A very basic example of an under-constrained circuit is the following NonIdentityFactors circuit:

```jsx
template NonIdentityFactors() {
	signal factorOne;
	signal factorTwo;
	signal val;

	val === factorOne * factorTwo;
}

component main{public [val]} = Factors();
```

This circuit is meant to prove that a prover knows two non identity factors (factors that don’t equal 1) of the public input *val*. The circuit is under-constrained because there is no constraint forcing the prover to use values other than 1 for *factorOne* or *factorTwo*. There is another missing constraint to ensure that *factorOne * factorTwo* is less than the scalar field order (See 3. Arithmetic Over/Under Flows for more details).

Under-constrained circuits attacks can vary widely depending on the constraints that are missing. In some cases it can lead to significant consequences like allowing a user to repeatedly drain funds (see Bugs in the Wild 5. and 6.). In order to prevent these bugs, it is important to test the circuit with edge cases and manually review the logic in depth. Formal verification tools are almost production ready and will be able to catch a lot of common under-constrained bugs, such as [ECNE by 0xPARC](https://0xparc.org/blog/ecne) and [Veridise's circom-coq](https://reviewgithub.com/rep/Veridise/circom-coq). Additional tooling to catch these vulnerabilities is in the works as well.

## <a name="nondeterministic-circuits">2. Nondeterministic Circuits</a>

Nondeterministic circuits are a subset of under-constrained circuits, usually because the missing constraints make the circuit nondeterministic. Nondeterminism, in this case, means that there are multiple ways to create a valid proof for a certain outcome. A common example of this is a nondeterministic nullifier generation process.

Nullifiers are often used in with zk applications to prevent double actions. For example, TornadoCash requires a nullifier to be generated and posted on-chain when a note commitment is spent. That way, if the user tries to spend the same note commitment a second time, they will have to post the same nullifier on-chain. Since the nullifier already exists, the smart contract will revert this second spend. The smart contract relies on a valid zk proof to ensure that the nullifier was generated correctly.

Note: Not all nondeterminstic circuits are vulnerable to attacks. In some cases, nondeterminism can allow for an optimized circuit while remaining secure. For example, the [circom-pairing library](https://github.com/yi-sun/circom-pairing/blob/master/docs/README.md#fp-element) represents field elements as integers A such that `0 <= A < p`, but only constrains `0 <= A`. So the `A < p` constraint is left out except for circuits that require it. In the cases where that constraint is not required, overflows will not break the assumptions of the circuit. However, it is still important to be aware of this possibility.

**Attack Scenario**

In a nondeterministic circuit for proving correct nullifier generation, there are multiple ways to generate a nullifier for the same note commitment. Each nullifier will be unique and posting the nullifier on-chain won’t prevent a double spend. The nondeterministic nature of the nullifier generation process allows users to spend a single note commitment multiple times.

**Preventative Techniques**

In order to prevent nondeterministic circuits, in-depth manual review of the circuit logic is needed. Constraints need to be added to ensure that the logic is deterministic where necessary. Often times, nondeterministic vulnerabilities can be fixed by adding additional constraints to make the logic deterministic.

## <a name="arithmetic-over-under-flows">3. Arithmetic Over/Under Flows</a>

Zk cryptography often involves modular arithmetic over a scalar field. This means that all operations are done modulo the order of the field. Circom circuits are built over a scalar field with the following order:

```jsx
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
```

It’s easy to forget this fact, and not account for over/under flows. This means that the following arithmetic statements are true in Circom:

```jsx
(0 - 1) === 21888242871839275222246405745257275088548364400416034343698204186575808495616;

(21888242871839275222246405745257275088548364400416034343698204186575808495616 + 1) === 0;
```

This can cause unintended consequences if there are no checks preventing these patterns.

**Attack Scenario**

For example, consider the following circuit that computes a user’s new balance:

```jsx
template getNewBalance() {
   signal input currentBalance;
   signal input withdrawAmount;
   signal output newBalance;

   newBalance <== currentBalance - withdrawAmount;
}
```

If a user inputs a `withdrawAmount` that is greater than their `currentBalance`, the `newBalance` output will underflow and will be an extremely large number close to `p`. This is clearly not what was intended by the circuit writer.

**The fix**

We can use the `LessThan` and `Num2Bits` templates defined by Circomlib to ensure the values we are working with are within the correct bounds, and will not cause overflows or underflows:

```jsx
// Ensure that both values are positive.
component n2b1 = Num2Bits(64);
n2b1.in <== withdrawAmount;

component n2b2 = Num2Bits(64);
n2b2.in <== currentBalance;

// Ensure that withdrawAmount <= currentBalance.
component lt = LessThan(64);
lt.in[0] = withdrawAmount;
lt.in[1] = currentBalance + 1;
lt.out === 1;
```

Here, `Num2Bits(n)` is used as a range check to ensure that the input lies in the interval `[0, 2^n)`. In particular, if `n` is small enough this ensures that the input is positive. If we forgot these range checks a malicious user could input a `withdrawAmount` equal to `p - 1`. This would satisfy the constraints defined by `LessThan` as long as the current balance is non-negative since `p - 1 = -1 < currentBalance`.

## <a name="mismatching-bit-lengths">4. Mismatching Bit Lengths</a>

Many of CircomLib’s circuits take in an expected number of bits. In order for their constraints and output to be accurate, the input parameters need to be constrained to that maximum number of bits outside of the CircomLib circuit. For example, the *LessThan* circuit expects *n* number of bits.

```jsx
template LessThan(n) {
    assert(n <= 252);
    signal input in[2];
    signal output out;

    component n2b = Num2Bits(n+1);

    n2b.in <== in[0]+ (1<<n) - in[1];

    out <== 1-n2b.out[n];
}
```

**Attack Scenario**

The *LessThan* circuit outputs 1 if *in[0] < in[1]*, and 0 otherwise. An attacker could use *in[0]* as a small number
and *in[1]* as a number with more than *n* bits. This would cause the *Num2Bits* input to underflow, and so the output
could be engineered to 0, even though *in[0] < in[1]*.

**Preventative Techniques**

In order to prevent this, bit length checks should be done on the inputs as well. This can be done by using CircomLib’s Num2Bits circuit. This circuit is already used in the LessThan circuit, but it is used on *in[0] + (1 << n) - in[1]* instead of on the inputs themselves. So the following Num2Bits constraints should be added as well:

```jsx
signal input1;
signal input2;
signal maxBits;

// Constrain input1 to maxBits
component bitCheck1 = Num2Bits(maxBits);
bitCheck1.in <== input1;

// Constrain input2 to maxBits
component bitCheck2 = Num2Bits(maxBits);
bitCheck2.in <== input2;

// Compare input1 to input2
component lt = LessThan(maxBits);
lt.in[0] <== input1;
lt.in[1] <== input2;

// Ensure input1 < input2
lt.out === 1;
```

## <a name="unused-pub-inputs">5. Unused Public Inputs Optimized Out</a>

Many circuits will have a variable as a public input, but won’t write any constraints on that variable. These public inputs without any constraints can act as key information when verifying the proof. However, as of Circom 2.0, the default r1cs compilation uses an optimizer. The optimizer will optimize these public inputs out of the circuit if they are not involved in any constraints.

```jsx
component UnusedPubInput() {
	signal inOne;
	signal inTwo;
	signal inThree;

	signal output out;

	out <== inOne + inTwo;
}

component main{public [inThree]} = UnusedPubInput();
```

In the example above, inThree will be optimized out. When submitting a proof to a verifier contract, any value for inThree will succeed on an existing proof.

**Attack Scenario**

Semaphore is a zero-knowledge application that allows users to prove membership of a group and send signals without revealing their identity. In this case, the signal that a user sends is hashed and included as a public input to the proof. If the Semaphore devs had not included any constraints on this variable, an attacker could take a valid proof of a user, modify the signal hash (public input) and replay the proof with the modified signal hash. This is essentially forging any signal they like.

**Preventative Techniques**

To prevent this over optimization, one can add a non-linear constraint that involves the public input. TornadoCash and Semaphore do this. TornadoCash used multiple non-linear constraints to prevent its public variables from being optimized out. Semaphore’s public “signalHash” input is intentionally added into a non-linear constraint (”signalHashSquared”) to prevent it from being optimized out.
[tornado-core/circuits/withdraw.circom](https://github.com/all-forks/tornado-core/blob/master/circuits/withdraw.circom)
```jsx
// Add hidden signals to make sure that tampering with recipient or fee will invalidate the snark proof
// Most likely it is not required, but it's better to stay on the safe side and it only takes 2 constraints
// Squares are used to prevent optimizer from removing those constraints
signal recipientSquare;
signal feeSquare;
signal relayerSquare;
signal refundSquare;
recipientSquare <== recipient * recipient;
feeSquare <== fee * fee;
relayerSquare <== relayer * relayer;
refundSquare <== refund * refund;
```

[Semaphore/semaphore.circom](https://github.com/semaphore-protocol/semaphore/blob/main/packages/circuits/semaphore.circom#L83-L85)

```jsx
// nLevels must be < 32.
template Semaphore(nLevels) {
  signal input identityNullifier;
  signal input identityTrapdoor;
  signal input treePathIndices[nLevels];
  signal input treeSiblings[nLevels];

  signal input signalHash;
  signal input externalNullifier;

  signal output root;
  signal output nullifierHash;

  component calculateSecret = CalculateSecret();
  calculateSecret.identityNullifier <== identityNullifier;
  calculateSecret.identityTrapdoor <== identityTrapdoor;

  signal secret;
  secret <== calculateSecret.out;

  component calculateIdentityCommitment = CalculateIdentityCommitment();
  calculateIdentityCommitment.secret <== secret;

  component calculateNullifierHash = CalculateNullifierHash();
  calculateNullifierHash.externalNullifier <== externalNullifier;
  calculateNullifierHash.identityNullifier <== identityNullifier;

  component inclusionProof = MerkleTreeInclusionProof(nLevels);
  inclusionProof.leaf <== calculateIdentityCommitment.out;

  for (var i = 0; i < nLevels; i++) {
      inclusionProof.siblings[i] <== treeSiblings[i];
      inclusionProof.pathIndices[i] <== treePathIndices[i];
  }

  root <== inclusionProof.root;

	// Dummy square to prevent tampering signalHash.
	signal signalHashSquared;
	signalHashSquared <== signalHash * signalHash;

	nullifierHash <== calculateNullifierHash.out;
}

component main {public [signalHash, externalNullifier]} = Semaphore(20);
```

## <a name="frozen-heart">6. Frozen Heart: Forging of Zero Knowledge Proofs</a>

If a zero-knowledge proof protocol is insecure, a malicious prover can forge a zk proof that will succeed verification. Depending on the details of the protocol, the forged proof can potentially be used to “prove” anything the prover wants. Additionally, many zk protocols use what is known as a Fiat-Shamir transformation. Insecure implementations of the Fiat-Shamir transformation can allow attackers to successfully forge proofs.

These types of vulnerabilities have been named “Frozen Heart” vulnerabilities by the TrailOfBits team. From their article (linked in references below):
>We’ve dubbed this class of vulnerabilities Frozen Heart. The word frozen is an acronym for FoRging Of ZEro kNowledge proofs, and the Fiat-Shamir transformation is at the heart of most proof systems: it’s vital for their practical use, and it’s generally located centrally in protocols. We hope that a catchy moniker will help raise awareness of these issues in the cryptography and wider technology communities. - Jim Miller, TrailOfBits

Many zk protocols are first developed as interactive protocols, where the prover and verifier need to send messages in multiple rounds of communication. The verifier must send random numbers to the prover, that the prover is unable to predict. These are known as "challenges". The prover must then compute their components of the proof based on these challenges. This requirement for multiple rounds of communication would greatly limit these protocol's practicality. The most common way around this is to use the Fiat-Shamir transformation that supports what is known as the "random oracle model". Essentially, the prover can automatically get the challenges by hashing certain inputs of the proof instead of waiting on the verifier for the challenges. The hashes of the proof inputs acts as a random oracle. This allows the communication to happen within 1 round - the prover generates the proof and sends it to the verifier. The verifier then outputs accept or reject.

As explained in the TrailOfBits’ explanation (linked in the references below), these bugs are widespread due to the general lack of guidance around implementing the Fiat-Shamir transformation for different protocols. Often times the protocols are implemented directly from the academic paper that first introduced the protocol. However, these papers do not include all of the necessary details to be weary of when writing it in code. TrailOfBits’ suggested solution is to produce better implementation guidance for developers, which is why they created [ZKDocs](https://www.zkdocs.com/).

**References**

1. [TrailOfBits explanation on the Frozen Heart bugs they discovered](https://blog.trailofbits.com/2022/04/13/part-1-coordinated-disclosure-of-vulnerabilities-affecting-girault-bulletproofs-and-plonk/)

## <a name="trusted-setup-leak">7. Trusted Setup Leak</a>

Many popular zk protocols require what is known as a trusted setup. The trusted setup is used to generate the parameters necessary for a prover to create sound zk proofs. However, the setup also involves parameters that need to be hidden to everyone. These are known as "toxic waste". If the toxic waste is revealed to a party, then they would be able to forge zk proofs for that system. The toxic waste is usually kept private in practice through the use of multi-party computation.

Older zk protocols such as Pinocchio and Groth16 require a new trusted setup for each unique circuit. This creates problems whenever a project needs to update their circuits because then they would need to redo the trusted setup. Newer protocols such as MARLIN and PLONK still require a trusted setup, but only once. These protocols' setup is known as "universal" since it can be used for multiple programs, making upgrades much easier. Other protocols such as Bulletproofs and STARKs do not require trusted setups at all.

See the references below for more details on toxic waste and how trusted setups work.

**References**

1. [Zcash Parameter Generation](https://z.cash/technology/paramgen/)
2. [How do trusted setups work? - Vitalik](https://vitalik.ca/general/2022/03/14/trustedsetup.html#:~:text=Many%20cryptographic%20protocols%2C%20especially%20in,some%20cryptographic%20protocol%20is%20run.)
3. [Setup Ceremonies](https://zkproof.org/2021/06/30/setup-ceremonies/)
4. [Zcash Soundness Bug](https://electriccoin.co/blog/zcash-counterfeiting-vulnerability-successfully-remediated/)

## <a name="assigned-not-constrained">8. Assigned but not Constrained</a>

A very common bug and misunderstanding is the difference between assignments and constraints. For zk circuits, constraints are the mathematical equations that must be satisfied by any given inputs for a proof to be valid. If any of the inputs result in one of the constraint equations to be incorrect, a valid proof is not possible (well, extremely unlikely).

Assignments, on the other hand, simply assign a value to a variable during proof generation. Assignments do not have to be followed for a valid proof to be created. Often times, an assignment can be used, in combination with other constraints, to reduce the total number of constraints used.

Constraints actually add equations to the R1CS file whereas assignments do not.

**Circom Case and Example**

A great example that highlights the difference between assignment and constraint is the `IsZero` circom circuit:

```jsx
pragma circom 2.0.0;

template IsZero() {
    signal input in;
    signal output out;
    signal inv;
    inv <-- in!=0 ? 1/in : 0;
    out <== -in*inv +1;
    in*out === 0;
}

component main {public [in]}= IsZero();
```

In circom, the `<--`, `-->` and `=` operators are assignments, whereas the `<==`, `==>`, and `===` operators are constraints. So, `inv` is assigned `1/in` if `in` is not `0` and is assigned `0` otherwise. This is not a constraint - a prover can assign whatever they want to `inv` as long as it satisfies the constraints. We will see, however, that even if the prover inputs values other than the expected assignment for `inv`, `IsZero` will still be constrained to output `1` if `in == 0` and `0` otherwise.

There are 2 cases to consider, `in` is zero and `in` is nonzero. If `in` is zero, then the first constraint `out <== -in*inv + 1` forces `out == 1`, and the second constraint `in*out === 0` is satisfied. So the circuit acts as expected, no matter what the prover inputs for `inv`. For the case that `in != 0`, then by the second constraint, `out` must be `0`. Therefore the first constraint must force that `-in*inv + 1 == 0`, and so `in*inv == 1`. This effectively constrains `inv` to equal the inverse of `in` as expected. Even though `inv` is assigned at will by the prover, the added constraints force it to actually be the inverse of `in` when `in != 0`. The circuit acts as expected for both cases of `in == 0` and when `in != 0`.

A good question is why don't we remove the first constraint and simplify the code to the following:

```jsx
template IsZero() {
    signal in;
    signal out;
    signal temp;
    temp <-- in!= 0 ? 0 : 1;
    out === temp;
}
```

The problem here is that `temp` is assigned to `in != 0 ? 0 : 1` and not actually constrained. So a trustworthy prover will always run this code and generate successful proofs, but a malicious prover can alter the code to assign anything to `temp`. A malicious prover could copy this circuit and change the `temp` assignment to `temp <-- 1;` so that the circuit always outputs `1`. Their proofs generated from their slightly changed code would successfully pass a verifier built from this example circuit. We need the `out <== -in*temp +1;` constraint to ensure that `temp` is actually the inverse of `in`.

Another good question is why don't we constrain instead of assign: `inv <== in!=0 ? 1/in : 0;`. This is because circom does not support the automatic constraint of a ternary operator. It adds more than one constraint behind the scenes which affects performance. For example, the [Mux1](https://github.com/iden3/circomlib/blob/master/circuits/mux1.circom) circuit is often used in place of the ternary operator, but it adds more than one constraint. So the authors of the `IsZero` circuit have found a creative way to reduce the constraint count.

**Halo2 Case**

This type of bug can easily happen with Halo2 circuits as well - maybe even more likely because assigning is done separately from constraints. In Halo2, often times the constraints are created in a `configure` function, while the assignments are done in an `assign` function. It is easy for developers to see that the circuit is satisfied because the `assign` function correctly gives the desired inputs. However, if the `configure` function is missing a constraint, a malicious prover can fork the code and change the `assign` function to target the missing constraint.

A good example of this bug is from the SHL and SHR opcode circuit for the PSE zkEVM. The opcode circuit takes as input a `shift` variable and a `shf0` variable:

```jsx
let shift = cb.query_word_rlc();
let shf0 = cb.query_cell();

```

Shf0 is assumed to be the first byte of the `shift` variable. There are later constraints added on `shf0` instead of `shift` because it is cheaper constraint-wise to only consider the first byte. However, there was a missing constraint forcing `shf0` to be the first byte of `shift`. It is easy to miss this because `shf0` and `shift` are properly assigned in the assign function:

```jsx
let shf0 = pop1.to_le_bytes()[0];
self.shift.assign(region, offset, Some(pop1.to_le_bytes()))?;
```

The fix was to add a constraint forcing `shf0` to equal the first byte of `shift`.

**Preventative Techniques**

To prevent these types of bugs, it is important to understand the ins and outs of whatever coding language was used to create the circuits. That way one can quickly identify what's constrained and what's assigned. Additionally, it is extremely important to go over each constraint in detail to ensure that the system is constrained to the exact expected behavior. Do not consider assignments when doing this, only the constraints. A great way to ensure your constraints are sufficient is through [formal verification](https://en.wikipedia.org/wiki/Formal_verification). Some tools are currently in the process that will help enable quick formal verification for circom and halo2 circuits.

**References**
1. [Circom Documentation](https://docs.circom.io/circom-language/signals/)
2. [CircomLib IsZero Circuit](https://github.com/iden3/circomlib/blob/cff5ab6288b55ef23602221694a6a38a0239dcc0/circuits/comparators.circom#L24-L34)
3. [PSE zkEVM Shf0 Bug](https://github.com/privacy-scaling-explorations/zkevm-circuits/issues/1124)

This repo was inspired by a few other github repos that also document common vulnerabilities (but for solidity) -
- [(Not So) Smart Contracts](https://github.com/crytic/not-so-smart-contracts)
- [Solidity Security Blog](https://github.com/sigp/solidity-security-blog)
- [List of Security Vulnerabilities](https://github.com/runtimeverification/verified-smart-contracts/wiki/List-of-Security-Vulnerabilities)

# <a name="zk-security-resources-header">Zk Security Resources</a>
1. ["Security of ZKP projects: same but different"](https://www.aumasson.jp/data/talks/zksec_zk7.pdf) by JP Aumasson @ [Taurus](https://www.taurushq.com/). Great slides outlining the different types of zk security vulnerabilities along with examples.
2. [Circomspect](https://github.com/trailofbits/circomspect) by [TrailOfBits](https://www.trailofbits.com/). A static analyzer for circom code to help detect vulnerabilities. The TrailOfBits [introduction post](https://blog.trailofbits.com/2022/09/15/it-pays-to-be-circomspect/) for this tool is a great read.

