---
title: "比特币源码分析-交易"
date: 2019-03-13T11:43:30+08:00
---
交易是比特币最核心的数据结构之一，交易的产生、共识、存储、传播都建立在其之上，所以我们先从交易展开，然后扩展到其他的部分。

我们可以使用Bitcoin Core的命令行界面（getrawtransaction和decodeawtransaction）来检索的“原始”交易，对其进行解码，并查看它包含的内容。

```
{
  "version": 1,
  "locktime": 0,
  "vin": [
    {
      "txid":"7957a35fe64f80d234d76d83a2a8f1a0d8149a41d81de548f0a65a8a999f6f18",
      "vout": 0,
      "scriptSig": "3045022100884d142d86652a3f47ba4746ec719bbfbd040a570b1deccbb6498c75c4ae24cb02204b9f039ff08df09cbe9f6addac960298cad530a863ea8f53982c09db8f6e3813[ALL] 0484ecc0d46f1918b30928fa0e4ed99f16a0fb4fde0735e7ade8416ab9fe423cc5412336376789d172787ec3457eee41c04f4938de5cc17b4a10fa336a8d752adf",
      "sequence": 4294967295
    }
 ],
  "vout": [
    {
      "value": 0.01500000,
      "scriptPubKey": "OP_DUP OP_HASH160 ab68025513c3dbd2f7b92a94e0581f5d50f654e7 OP_EQUALVERIFY OP_CHECKSIG"
    },
    {
      "value": 0.08450000,
      "scriptPubKey": "OP_DUP OP_HASH160 7f9b1a7fb68d60c536c2fd8aeaa53a8f3cc025a8 OP_EQUALVERIFY OP_CHECKSIG",
    }
  ]
}
```
可以发现交易中有vin，vout这两个关键成员变量。

这两个变量分别代表着比特币交易的 “收入” 与 “支出”。比特币的交易并不是记录账户形的数据变化(比如我们采用银行的模型来描述 A 向 B 转账100元，那么银行在记录这个转账的过程中会出现3个记录，这三个记录连成了一个 Transaction (事务)过程：A 的账户减少100元，记录的id为 tid1，B的账户加上100元，记录的id为 tid2，一笔转账记录记录了tid1向tid2转账了100元，成为A账户减少与B账户增加的“关系连接”。)，而是日志形：比特币的Tx 只记录A 向 B 转账的这个“关系连接”，这条日志记录只包含了 A 向 B 转账了 100 元这条信息。而这里的 in 就是记录着 从 ‘’谁“ 来(目前先简单的这样看，实际完全不止这样，后文会慢慢重新解释)， out 就是转给了谁，而转账了多少钱是包含在 out 中的。在中本聪的命名风格是使用一个前缀代表这个属性的类型，如果是flag还会加上一个f。所以这里的 vin/vout 就是指代in 和 out 都是 vector 类型，所以这里我们可以看到，一个 Tx 的 in/out 是可以有多个的。在后文中，我们称呼 in 为 TxIn，out 为 TxOut (注意这里把 in out 比作两个人是完全不恰当的，之后会重新描述)



CTransaction 类就是我们常说的bitcoin的 “交易” (一般称为 Tx, 后文也会沿用这种说法)

Tx 类存储着上述两个关键变量

vector<CTxIn> vin;
vector<CTxOut> vout;

**下面引入Tx的源码：**
```
/** The basic transaction that is broadcasted on the network and contained in blocks.  
 * A transaction can contain multiple inputs and outputs.
 * 下面就是在网络中广播然后被打包进区块的最基本的交易的结构，一个交易可能包含多个交易输入和输出。
 */
class CTransaction
{
public:
    // Default transaction version. 默认交易版本
    static const int32_t CURRENT_VERSION=2;

    // Changing the default transaction version requires a two step process: first
    // adapting relay policy by bumping MAX_STANDARD_VERSION, and then later date
    // bumping the default CURRENT_VERSION at which point both CURRENT_VERSION and
    // MAX_STANDARD_VERSION will be equal.
    static const int32_t MAX_STANDARD_VERSION=2;

    // The local variables are made const to prevent unintended modification
    // without updating the cached hash value. However, CTransaction is not
    // actually immutable; deserialization and assignment are implemented,
    // and bypass the constness. This is safe, as they update the entire
    // structure, including the hash.
    /** 下面这些变量都被定义为常量类型，从而避免无意识的修改了交易而没有更新缓存的hash值；
    * 但还是可以通过重新构造一个交易然后赋值给当前交易来进行修改，这样就更新了交易的所有内容
    */
    const int32_t nVersion;  // 版本
    const std::vector<CTxIn> vin; // 交易输入
    const std::vector<CTxOut> vout; // 交易输出
    const uint32_t nLockTime; // 锁定时间

private:
    /** Memory only. */
    const uint256 hash;

    uint256 ComputeHash() const;

public:
    /** Construct a CTransaction that qualifies as IsNull() */
    CTransaction();

    /** Convert a CMutableTransaction into a CTransaction. */
    CTransaction(const CMutableTransaction &tx);
    CTransaction(CMutableTransaction &&tx);

    template <typename Stream>
    inline void Serialize(Stream& s) const {
        SerializeTransaction(*this, s);
    }

    /** This deserializing constructor is provided instead of an Unserialize method.
     *  Unserialize is not possible, since it would require overwriting const fields. */
    template <typename Stream>
    CTransaction(deserialize_type, Stream& s) : CTransaction(CMutableTransaction(deserialize, s)) {}

    bool IsNull() const {
        return vin.empty() && vout.empty();
    }

    const uint256& GetHash() const {
        return hash;
    }

    // Compute a hash that includes both transaction and witness data
    uint256 GetWitnessHash() const;

    // Return sum of txouts.
    CAmount GetValueOut() const; // 返回交易输出金额之和
    // GetValueIn() is a method on CCoinsViewCache, because
    // inputs must be known to compute value in.

    /**
     * Get the total transaction size in bytes, including witness data.
     * "Total Size" defined in BIP141 and BIP144.
     * @return Total transaction size in bytes
     */
    unsigned int GetTotalSize() const; // 返回交易大小

    bool IsCoinBase() const  // 判断是否是coinbase交易
    {
        return (vin.size() == 1 && vin[0].prevout.IsNull());
    }

    friend bool operator==(const CTransaction& a, const CTransaction& b)
    {
        return a.hash == b.hash;
    }

    friend bool operator!=(const CTransaction& a, const CTransaction& b)
    {
        return a.hash != b.hash;
    }

    std::string ToString() const;

    bool HasWitness() const
    {
        for (size_t i = 0; i < vin.size(); i++) {
            if (!vin[i].scriptWitness.IsNull()) {
                return true;
            }
        }
        return false;
    }
};
```
从这步起，我们直接抛弃 ”两个人之间进行交易“这样的概念，直接认为在比特币的交易系统中是不具备”所有人“这样概念(这样肯定很奇怪因为都没有所有人了比特币还有什么意义，但之后会解释)，而只是把 ”交易“ 看作 ”比特币流“ 的中转的中转节点，就像水流分叉合并的那些节点一样：

典型的 bitcoin 交易链：
![image](http://upload-images.jianshu.io/upload_images/16810203-c0ba3d7968a925bd.jpg?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

bitcoin 有一个相当相当重要的规定就是 每个 Tx 的 所有 In 进入了货币流必须在这个交易中全部流出去(流出去不代表成为其他Tx的In，而是必须要成为一个 TxOut。)

举例来说：如果A 转账 100 给 B，但是现在A能控制的Out 有2个，一个是Out1是60，一个是Out2是50，那么A一检查自己的Out就会发现，60和50都不够100，那么就只能把 Out1 和 Out2 都作为当前要生产的 Tx 的 In。但是这种情况下，所有In的和就大于要支出的 100了。那么如果不付交易费的话，除去转账给 B 的 100 所对应的当前Tx的 Out，那么还会多出10。在bitcoin中就强行规定，这多出的10也要创建一个 Out 来锁住这10 块，以规定每笔交易的 In 和 Out 的总数都要相同。那么因为这 10 相当于我们通俗意义上的“找零”，所以这个 10 块的 Out 的锁当然就是 A 自己可以控制的锁，相当于这个Out指向了自己。

所以这样我们可以看到，一个交易只含有一个输入和一个输出，那么这个交易并不是看作一个人转账到了另一个人身上，而是把比特币看作像流水一样的货币流，从某个地方流入到了这个交易的输入，由从这个交易的输出流到另一个地方去。那么接下来的问题就显而易见了--如何控制货币流的流动？答案你就是 CTxIn 和 CTxOut 的属性。

我们来看下这两个类
**CTxIn：**
```
class CTxIn{
public:
    COutPoint prevout;
    CScript scriptSig;
    unsigned int nSequence;
}; 
```
从哪个Tx流入的信息就是由 COutPoint 所记录。

nSequence 在 v0.1 中没有起到什么作用，也不会用来作校验，但是这个字段今后被作为了其他用途，而且成为了bitcoin的一个软分叉的最佳例子。

**COutPoint的属性：**
```
/** An outpoint - a combination of a transaction hash and an index n into its vout. 
* COutPoint主要用在交易的输入CTxIn中，用来确定当前输出的来源，
* 包括前一笔交易的hash，以及对应前一笔交易中的第几个输出的序列号。
*/
class COutPoint
{
public:
    uint256 hash; // 交易的哈希
    uint32_t n;  // 对应的序列号

    COutPoint() { SetNull(); }
    COutPoint(uint256 hashIn, uint32_t nIn) { hash = hashIn; n = nIn; }

    ADD_SERIALIZE_METHODS;  // 用来序列化数据结构，方便存储和传输

};
```
**CTxOut：**
```
class CTxOut{
public:
    int64 nValue;
    CScript scriptPubKey;
};
```
value 就是记录着”从这个出口会流出多少“的信息。简单的来说就是可以理解为通俗意义上的转账了。但是我们这里还是强调，首先理解bitcoin先抛开 支付交易 等概念，而是把 bitcoin 看成流动的水，而这里的 value 就是记录从这里会流出多少 bitcoin 的意思。显然一个 Tx 的所有 TxOut 的 value 的和 应该等于 所有 TxIn 流入的总和 (不考虑手续费，弱考虑手续费就是小于等于)，否则这笔交易就应该认为是非法的(不能凭空多出钱来)。


后文将对 CTxIn.scriptSig, CTxOut.scriptPubKey 进行解读

