
#include "serialize.h"
#include <cassert>
int main(){
    miq::Transaction tx; miq::TxIn in; in.prev.txid=std::vector<uint8_t>(32,1); in.prev.vout=0; in.sig=std::vector<uint8_t>(64,2); in.pubkey=std::vector<uint8_t>(33,3); tx.vin.push_back(in);
    miq::TxOut o; o.value=123; o.pkh=std::vector<uint8_t>(20,4); tx.vout.push_back(o);
    auto b = miq::ser_tx(tx); miq::Transaction tx2; assert(miq::deser_tx(b, tx2));
    return 0;
}
