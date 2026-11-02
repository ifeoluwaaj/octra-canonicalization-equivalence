// Harness: exercise REAL webcli tx_builder.hpp serialization functions.
// Prints one JSON object per case: {name, wire, signing, hash_preimage, tx_hash}
#include "lib/tx_builder.hpp"
#include <cstdio>
#include <iostream>

extern "C" void randombytes(unsigned char* p, unsigned long long n) {
    for (unsigned long long i = 0; i < n; ++i) p[i] = 0;
}

static std::string jesc(const std::string& s) {
    std::string r;
    for (unsigned char c : s) {
        if (c == '"') r += "\\\"";
        else if (c == '\\') r += "\\\\";
        else if (c < 0x20 || c == 0x7f) {
            char buf[8];
            std::snprintf(buf, sizeof buf, "\\u%04x", c);
            r += buf;
        } else r += (char)c;
    }
    return r;
}

int main() {
    using octra::Transaction;
    struct Case { const char* name; Transaction tx; bool has_pk, has_msg, has_ed; };
    std::vector<Case> cases;

    auto mk = [](std::string from, std::string to, std::string amount, int nonce,
                 std::string ou, double ts, std::string op, std::string sig,
                 std::string pk, std::string msg, std::string ed) {
        Transaction t;
        t.from = from; t.to_ = to; t.amount = amount; t.nonce = nonce; t.ou = ou;
        t.timestamp = ts; t.op_type = op; t.signature = sig;
        t.public_key = pk; t.message = msg; t.encrypted_data = ed;
        return t;
    };

    cases.push_back({"plain", mk("octAlice","octBob","7",1,"1000",1700000000.0,"standard","c2lnbmVk","cGs=","",""), true,false,false});
    cases.push_back({"decimal_padding", mk("octAlice","octBob","0007",1,"001000",1700000000.0,"standard","c2lnbmVk","cGs=","",""), true,false,false});
    cases.push_back({"frac_ts_17digit", mk("octAlice","octBob","0",2,"1000",1700000000.1234567,"stealth","c2ln","cGs=","{\"proof\":\"AA==\"}","cipher"), true,true,true});
    cases.push_back({"tiny_ts", mk("octBob","octBob","0",3,"1000",1.2345678901234567e-06,"claim","claim","cGs=","line\n\t\u0001\u007f\u03b1","cipher"), true,true,true});
    cases.push_back({"big_ts", mk("octAlice","octBob","1",4,"1000",1.2345678901234567e+20,"standard","c2ln","cGs=","",""), true,false,false});
    cases.push_back({"negzero_ts", mk("octAlice","octBob","1",5,"1000",-0.0,"standard","c2ln","cGs=","",""), true,false,false});
    cases.push_back({"small_ts", mk("octAlice","octBob","1",6,"1000",1e-07,"standard","c2ln","cGs=","",""), true,false,false});
    cases.push_back({"tenth_ts", mk("octAlice","octBob","1",7,"1000",0.1,"standard","c2ln","cGs=","",""), true,false,false});
    cases.push_back({"no_pk", mk("octAlice","octBob","1",8,"1000",1700000000.5,"standard","c2ln","","",""), false,false,false});
    cases.push_back({"msg_only", mk("octAlice","octBob","0",9,"1000",1730000000.25,"program_exec","c2ln","","[123456789012345678901234567890,\"a\\u007fb\"]",""), true,true,false});
    cases.push_back({"ed_only", mk("octAlice","octBob","0",10,"1000",1730000000.0,"program_deploy","c2ln","cGs=","","cGFja2FnZQ=="), true,false,true});
    cases.push_back({"ctrl_msg", mk("octAlice","octBob","0",11,"1000",1730000000.75,"circle_call","c2ln","cGs=","del:\u007f:bs:\b:ff:\f:cr:\r:esc:\u001b:uni:\u03b1:x",""), true,true,false});
    cases.push_back({"empty_op", mk("octAlice","octBob","5",12,"1000",1730000000.25,"","c2ln","cGs=","",""), true,false,false});

    std::string out = "[";
    for (size_t i = 0; i < cases.size(); ++i) {
        const auto& c = cases[i];
        try {
            std::string signing = octra::signing_json(c.tx);
            std::string hash_pre = octra::hash_json(c.tx);
            std::string wire = octra::build_tx_json(c.tx).dump();
            std::string txh = octra::tx_hash(c.tx);
            out += (i ? "," : "");
            out += "{\"name\":\"" + std::string(c.name) + "\",\"wire\":\"" + jesc(wire)
                + "\",\"signing\":\"" + jesc(signing) + "\",\"hash_pre\":\"" + jesc(hash_pre)
                + "\",\"tx_hash\":\"" + txh + "\"}";
        } catch (const std::exception& e) {
            out += (i ? "," : "");
            out += "{\"name\":\"" + std::string(c.name) + "\",\"error\":\"" + jesc(e.what()) + "\"}";
        }
    }
    out += "]";
    std::cout << out << std::endl;
    return 0;
}
