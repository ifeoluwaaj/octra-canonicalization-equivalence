(* Replicates lite_node lib/core/transaction.ml: of_yojson field extraction +
   serialize_for_signing + hash preimage, using the REAL Yojson + Zarith that
   lite_node links. Compares against webcli C++ output in canon_cpp.json. *)
open Yojson.Safe.Util

type op = string

type tx = {
  from_ : string; to_ : string; amount : Z.t; nonce : int; ou : Z.t;
  timestamp : float; signature : string; public_key : string option;
  message : string option; op_type : op; encrypted_data : string option;
}

let opt_json = function None -> `Null | Some v -> `String v

let of_yojson (v : Yojson.Safe.t) : tx =
  let str k = match member k v with `String s -> s | _ -> failwith ("str " ^ k) in
  let int k = match member k v with `Int n -> n | _ -> failwith ("int " ^ k) in
  let z k = match member k v with
    | `String s -> (try Z.of_string s with _ -> failwith ("z " ^ k))
    | `Int n -> Z.of_int n
    | _ -> failwith ("z " ^ k) in
  let fl k = match member k v with
    | `Float x -> x
    | `Int n -> float_of_int n
    | _ -> failwith ("fl " ^ k) in
  let opt k = match member k v with `String s -> Some s | _ -> None in
  let op = match member "op_type" v with
    | `String s -> s
    | `Null -> "standard"
    | _ -> failwith "op" in
  { from_ = str "from"; to_ = str "to_"; amount = z "amount"; nonce = int "nonce";
    ou = z "ou"; timestamp = fl "timestamp"; signature = str "signature";
    public_key = opt "public_key"; message = opt "message"; op_type = op;
    encrypted_data = opt "encrypted_data" }

let serialize_for_signing tx =
  let base = [
    "from", `String tx.from_; "to_", `String tx.to_;
    "amount", `String (Z.to_string tx.amount);
    "nonce", `Int tx.nonce;
    "ou", `String (Z.to_string tx.ou);
    "timestamp", `Float tx.timestamp;
    "op_type", `String tx.op_type;
  ] in
  let fields = match tx.encrypted_data with
    | Some ed -> base @ ["encrypted_data", `String ed] | None -> base in
  let fields = match tx.message with
    | Some m -> fields @ ["message", `String m] | None -> fields in
  `Assoc fields |> Yojson.Safe.to_string

let hash_preimage tx =
  `Assoc [
    "from", `String tx.from_; "to_", `String tx.to_;
    "amount", `String (Z.to_string tx.amount);
    "nonce", `Int tx.nonce;
    "ou", `String (Z.to_string tx.ou);
    "timestamp", `Float tx.timestamp;
    "signature", `String tx.signature;
    "op_type", `String tx.op_type;
    "public_key", opt_json tx.public_key;
    "message", opt_json tx.message;
    "encrypted_data", opt_json tx.encrypted_data;
  ] |> Yojson.Safe.to_string

let () =
  let cases = Yojson.Safe.from_file "canon_cpp.json" in
  let results = `List (List.map (fun case ->
    let name = case |> member "name" |> to_string in
    match member "error" case with
    | `String e -> `Assoc ["name", `String name; "status", `String "cpp_error"; "detail", `String e]
    | _ ->
      let wire = case |> member "wire" |> to_string in
      let cpp_signing = case |> member "signing" |> to_string in
      let cpp_hash = case |> member "hash_pre" |> to_string in
      (try
        let tx = of_yojson (Yojson.Safe.from_string wire) in
        let ocaml_signing = serialize_for_signing tx in
        let ocaml_hash = hash_preimage tx in
        `Assoc [
          "name", `String name;
          "signing_match", `Bool (ocaml_signing = cpp_signing);
          "hash_match", `Bool (ocaml_hash = cpp_hash);
          "ocaml_signing", `String ocaml_signing;
          "ocaml_hash", `String ocaml_hash;
        ]
      with e -> `Assoc ["name", `String name; "status", `String "ocaml_error";
                        "detail", `String (Printexc.to_string e)]))
    (to_list cases)) in
  print_endline (Yojson.Safe.to_string results)
