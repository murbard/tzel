(* Binary Merkle tree with mrklSP__ personalization.
   Used for both the commitment tree (depth 48) and auth key tree (depth 10).

   The append-only tree uses an incremental algorithm that stores only
   O(depth) nodes, not the full 2^depth leaf array. *)

(* Compute zero nodes: zero[0] = [0u8;32], zero[d+1] = H_merkle(zero[d], zero[d]) *)
let zero_nodes max_depth =
  let nodes = Array.make (max_depth + 1) Felt.zero in
  for d = 0 to max_depth - 1 do
    nodes.(d + 1) <- Hash.hash_merkle nodes.(d) nodes.(d)
  done;
  nodes

(* Build a Merkle root from a list of leaves, padding with zeros to 2^depth.
   Only suitable for small trees (auth tree, depth <= ~20). *)
let root_of_leaves ~depth leaves =
  let n = 1 lsl depth in
  let zeros = zero_nodes depth in
  let layer = Array.make n Felt.zero in
  List.iteri (fun i v ->
    if i < n then layer.(i) <- v) leaves;
  for i = List.length leaves to n - 1 do
    layer.(i) <- zeros.(0)
  done;
  let current = ref layer in
  for _d = 0 to depth - 1 do
    let size = Array.length !current / 2 in
    let next = Array.make size Felt.zero in
    for i = 0 to size - 1 do
      next.(i) <- Hash.hash_merkle (!current).(2*i) (!current).(2*i+1)
    done;
    current := next
  done;
  (!current).(0)

(* Compute a Merkle authentication path for leaf at position pos.
   Only suitable for small trees. *)
let auth_path ~depth leaves pos =
  let n = 1 lsl depth in
  let zeros = zero_nodes depth in
  let layer = Array.make n Felt.zero in
  List.iteri (fun i v ->
    if i < n then layer.(i) <- v) leaves;
  for i = List.length leaves to n - 1 do
    layer.(i) <- zeros.(0)
  done;
  let path = Array.make depth Felt.zero in
  let current = ref layer in
  for d = 0 to depth - 1 do
    let idx = (pos lsr d) lxor 1 in
    path.(d) <- (!current).(idx);
    let size = Array.length !current / 2 in
    let next = Array.make size Felt.zero in
    for i = 0 to size - 1 do
      next.(i) <- Hash.hash_merkle (!current).(2*i) (!current).(2*i+1)
    done;
    current := next
  done;
  path

(* Verify a Merkle proof *)
let verify_path ~depth leaf pos path root =
  let node = ref leaf in
  for d = 0 to depth - 1 do
    let bit = (pos lsr d) land 1 in
    if bit = 0 then
      node := Hash.hash_merkle !node path.(d)
    else
      node := Hash.hash_merkle path.(d) !node
  done;
  Felt.equal !node root

(* Compute root from leaf and path *)
let root_from_path ~depth leaf pos path =
  let node = ref leaf in
  for d = 0 to depth - 1 do
    let bit = (pos lsr d) land 1 in
    if bit = 0 then
      node := Hash.hash_merkle !node path.(d)
    else
      node := Hash.hash_merkle path.(d) !node
  done;
  !node

(* Incremental append-only Merkle tree.
   Uses O(depth) storage: stores the "filled subtree" hashes along the
   left frontier. This is the standard approach for append-only trees
   used in Zcash, Ethereum deposit contracts, etc.

   filled.(d) = root of the complete subtree at depth d on the left frontier,
   or None if that level hasn't been filled yet. *)
type tree = {
  depth : int;
  filled : Felt.t option array;  (* depth elements: filled subtrees *)
  zeros : Felt.t array;          (* precomputed zero nodes *)
  mutable size : int;
}

let create ~depth =
  let zeros = zero_nodes depth in
  { depth; filled = Array.make depth None; zeros; size = 0 }

(* Append a leaf and return the new root *)
let append t leaf =
  let max_size = 1 lsl t.depth in
  if t.size >= max_size then
    failwith "Merkle tree full";
  let pos = t.size in
  (* Walk up from leaf level, combining with filled subtrees or zeros *)
  let node = ref leaf in
  for d = 0 to t.depth - 1 do
    let bit = (pos lsr d) land 1 in
    if bit = 0 then begin
      (* This is a left child; save the current hash as the filled subtree *)
      t.filled.(d) <- Some !node;
      (* Combine with zero on the right for root computation *)
      node := Hash.hash_merkle !node t.zeros.(d)
    end else begin
      (* This is a right child; combine with the saved left *)
      let left = match t.filled.(d) with
        | Some h -> h
        | None -> t.zeros.(d) in
      node := Hash.hash_merkle left !node
    end
  done;
  t.size <- t.size + 1;
  !node

(* Compute the current root without appending *)
let root t =
  if t.size = 0 then
    t.zeros.(t.depth)
  else begin
    (* Reconstruct from filled array *)
    let pos = t.size - 1 in
    (* We need to recompute: walk up using the last-inserted leaf's position *)
    (* Actually, we need to compute the root considering all filled subtrees.
       The simplest correct approach: track the root during append. *)
    (* Let's use a different approach: compute root from the frontier. *)
    let node = ref t.zeros.(0) in
    for d = 0 to t.depth - 1 do
      (* At each level, if the tree has a complete subtree on the left at this level,
         use it. Otherwise use the zero. *)
      let bit = (t.size lsr d) land 1 in
      if bit = 1 then begin
        let left = match t.filled.(d) with
          | Some h -> h
          | None -> t.zeros.(d) in
        node := Hash.hash_merkle left !node
      end else begin
        node := Hash.hash_merkle !node t.zeros.(d)
      end
    done;
    ignore pos;
    !node
  end

(* Store leaves for path generation in large trees *)
type tree_with_leaves = {
  tr : tree;
  mutable leaves : Felt.t list;  (* reversed for efficient append *)
}

let create_with_leaves ~depth =
  { tr = create ~depth; leaves = [] }

let append_with_leaves t leaf =
  let root = append t.tr leaf in
  t.leaves <- leaf :: t.leaves;
  root

let root_with_leaves t = root t.tr

let size_with_leaves t = t.tr.size

(* Get all leaves in order *)
let get_leaves t = List.rev t.leaves

(* Compute auth path for a leaf in a tree_with_leaves.
   For large trees, this recomputes from the leaf list.
   For production use, a more efficient structure would be needed. *)
let path_with_leaves t pos =
  if pos >= t.tr.size then
    failwith "Position out of range";
  let all_leaves = get_leaves t in
  (* Build a sparse path computation *)
  let depth = t.tr.depth in
  let path = Array.make depth Felt.zero in
  (* We compute layer by layer, but only for the nodes we need *)
  (* For each depth level, we need the sibling of the node on the path from leaf to root *)
  let current_layer = Hashtbl.create 16 in
  (* Initialize with all leaves *)
  List.iteri (fun i v -> Hashtbl.replace current_layer i v) all_leaves;
  let layer_ref = ref current_layer in
  for d = 0 to depth - 1 do
    let sibling_idx = (pos lsr d) lxor 1 in
    path.(d) <- (match Hashtbl.find_opt !layer_ref sibling_idx with
      | Some h -> h
      | None -> t.tr.zeros.(d));
    (* Build next layer *)
    let next = Hashtbl.create (Hashtbl.length !layer_ref / 2 + 1) in
    Hashtbl.iter (fun idx v ->
      let parent = idx / 2 in
      let is_left = idx mod 2 = 0 in
      let existing = Hashtbl.find_opt next parent in
      ignore existing;
      if is_left then begin
        let right = match Hashtbl.find_opt !layer_ref (idx + 1) with
          | Some h -> h
          | None -> t.tr.zeros.(d) in
        Hashtbl.replace next parent (Hash.hash_merkle v right)
      end else begin
        let left = match Hashtbl.find_opt !layer_ref (idx - 1) with
          | Some h -> h
          | None -> t.tr.zeros.(d) in
        if not (Hashtbl.mem next parent) then
          Hashtbl.replace next parent (Hash.hash_merkle left v)
      end
    ) !layer_ref;
    layer_ref := next
  done;
  path
