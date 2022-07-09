package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	_ "strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"

    "reflect"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
const SaltLength = 16
const HMACLength = 64 // it uses sha512 as the underlying hash function

type User struct {
    username string
    password string

    // the salt for HashedPassword
    PasswordSalt []byte
    // hash(PasswordSalt || password)
    HashedPassword []byte

    ArgonSalt []byte
    rootKey []byte // = f(ArgonSalt, password)

    // Initialize PrviateKey so that other users can send messages to this user
    privateKey userlib.PKEDecKey
    Encrypted_privateKey []byte
    // Initialize SignKey so that this user can gaurantee integrity of its message
    signKey userlib.DSSignKey
    Encrypted_signKey []byte

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

// This data struct will be encrypted by each user's password-derived key
type FileMetadata struct {
    IsOwner bool
    Filename string

    // add an indirection layer for head and tail
    FileInfoNodeUUID uuid.UUID

    // ================== Non-owner =====================
    // non-owner will use this data struct to access the lockbox
    LockboxInfo LockboxInfo
    // ==================================================

    // ================== Owner =========================
    // Only the owner will use this data structure
    SharedUser2LockboxInfo map[string]LockboxInfo

    // Only the owner will directly store its lockbox in this data struct
    Lockbox Lockbox
    // ==================================================

    // Record the # of revoked users to generate different hash values
    // for the FileInfoNodeUUID and FileContentNodeUUID
    NumRevokedUsers int
}

func InitFileMetadata(
    username string, filename string) *FileMetadata{
    var filemetadata FileMetadata
    filemetadata.IsOwner = true
    filemetadata.Filename = filename
    filemetadata.NumRevokedUsers = 0
    // NOTE: the uuid id is f(owner's username, owner's filename, number of revoked users)
    filemetadata.FileInfoNodeUUID = GetFileInfoUUID(
        username, filename, filemetadata.NumRevokedUsers)

    // Create this file's root key
    filemetadata.Lockbox.InitLockbox()

    // Initiaize a FileInfoNode
    var fileInfoNode FileInfoNode

    // Encrypt the FileInfoNode via the file root key
    ciphertext_and_hmac := EncryptThenMac(
            filemetadata.Lockbox.GetEncryptKey(),
            filemetadata.Lockbox.GetHMACKey(), &fileInfoNode)

    // Store in the persistent storage (NOTE: we won't check when writing stuff)
    // Put the encrypted and hmac onto the datastore
    userlib.DatastoreSet(filemetadata.FileInfoNodeUUID, ciphertext_and_hmac)

    return &filemetadata
}

func InitFileMetadataFromInivitation(filename string, invitation *Invitation) *FileMetadata{
    var filemetadata FileMetadata
    filemetadata.IsOwner = false // not an owner
    filemetadata.Filename = filename // the new filename under this user's namespace
    // Need to -> {head, tail}
    filemetadata.FileInfoNodeUUID = invitation.FileInfoNodeUUID
    // store {how to open the lockbox, how to open the lockbox}
    filemetadata.LockboxInfo = invitation.LockboxInfo
    return nil
}

// EncryptThenMac an arbitrary struct
func EncryptThenMac(encryptKey []byte, hmacKey []byte, v interface{}) []byte{
    if len(encryptKey) != 16 || len(hmacKey) != 16{
        panic("len(encrpytion) and len(hmacKey) should be 16")
    }
    serialized, err := json.Marshal(v)
    if err != nil {
        panic(err)
    }
    ciphertext := userlib.SymEnc(encryptKey, userlib.RandomBytes(16), serialized)
    hmac, err := userlib.HMACEval(hmacKey, ciphertext)
    if err != nil {
        panic(err)
    }

    combined := append(ciphertext, hmac...)
    return combined
}

// CheckThenDecrypt an arbitrary struct
func CheckThenDecrypt(encryptKey []byte, hmacKey []byte,
                      ciphertext_and_hmac []byte, out interface{}) error{
    // Make sure `out` is a pointer so that Unmarshal will write stuff into out
    if reflect.ValueOf(out).Type().Kind() != reflect.Pointer{
        panic("out should be a pointer type")
    }

    if len(encryptKey) != 16 || len(hmacKey) != 16{
        panic("len(encrpytion) and len(hmacKey) should be 16")
    }
    if len(ciphertext_and_hmac) < HMACLength {
        return errors.New("Detect a malicious action: Length should be >= 64")
    }
    n := len(ciphertext_and_hmac)
    ciphertext, hmac := ciphertext_and_hmac[:n-HMACLength],
                        ciphertext_and_hmac[n-HMACLength:]
    regen_hmac, err := userlib.HMACEval(hmacKey, ciphertext)
    if err != nil {
        panic(err)
    }
    if !userlib.HMACEqual(regen_hmac, hmac) {
        return errors.New("Detect a malicious action: the HMAC of the ciphertext does not match")
    }
    serialized := userlib.SymDec(encryptKey, ciphertext)
    err = json.Unmarshal(serialized, out)
    return err
}

/*
Logical view:
----------------
| FileInfoNode |
| Head---------|--> |FileContent-dummy| -> |FileContent-1| -> |FileContent-2|
| Tail---------|-----------------------------------------------------^
----------------
*/
type FileInfoNode struct {
    FileContentHead uuid.UUID
    FileContentTail uuid.UUID
    Length int // a counter to prevent FileContentNode swapping attack
}

func (fInfoNode *FileInfoNode) append_new_node(lockbox *Lockbox, content []byte) error{

    var nil_uuid uuid.UUID

    var fileContentNode *FileContentNode = InitFileContentNode(content)
    var new_uuid uuid.UUID = uuid.New() // Generate a random uuid

    if reflect.DeepEqual(fInfoNode.FileContentTail, nil_uuid){
        // Point to a new node
        fInfoNode.FileContentHead = new_uuid
        fInfoNode.FileContentTail = new_uuid

        // Write to the datastore
        WriteToDatastoreFromStruct(
            lockbox.GetContentEncryptKey(fInfoNode.Length),
            lockbox.GetContentHMACKey(fInfoNode.Length),
            new_uuid, fileContentNode)
    }else{
        // Load the tail node
        var tailContentNode FileContentNode
        // Using Key(fInfoNode.Length-1) to decrypt and check the tail node
        err := LoadStructFromDatastore(
                lockbox.GetContentEncryptKey(fInfoNode.Length-1),
                lockbox.GetContentHMACKey(fInfoNode.Length-1),
                fInfoNode.FileContentTail, &tailContentNode)
        // If err, that means the tail node is tampered with
        if err != nil {
            return err
        }
        // Update the tail
        oldtail_uuid := fInfoNode.FileContentTail
        fInfoNode.FileContentTail = new_uuid
        // The tail will point to the new tail
        tailContentNode.Next = new_uuid
        // Write to the datastore
        // * Update the old tail (because we update the `Next` field)
        // * Store the new tail
        WriteToDatastoreFromStruct(
            lockbox.GetContentEncryptKey(fInfoNode.Length-1),
            lockbox.GetContentHMACKey(fInfoNode.Length-1),
            oldtail_uuid, &tailContentNode)
        WriteToDatastoreFromStruct(
            lockbox.GetContentEncryptKey(fInfoNode.Length),
            lockbox.GetContentHMACKey(fInfoNode.Length),
            new_uuid, fileContentNode)
    }
    // Increment the length
    fInfoNode.Length++
    return nil
}

func (fInfoNode *FileInfoNode) load_content(
            lockbox *Lockbox) ([]byte, error){

    var head, tail, cur uuid.UUID
    head, tail = fInfoNode.FileContentHead, fInfoNode.FileContentTail
    cur = head

    var content []byte

    // Traversing the linked list
    for i := 0; i < fInfoNode.Length; i++{
        encKey := lockbox.GetContentEncryptKey(i)
        hmacKey := lockbox.GetContentHMACKey(i)
        
        var curContentNode FileContentNode
        err := LoadStructFromDatastore(encKey, hmacKey, cur, &curContentNode)

        if err != nil{
            // err because of malicious actions
            return nil, err
        }

        // append the content
        content = append(content, curContentNode.Content...)

        // sanity check: check if the last node is the same as tail
        if i == fInfoNode.Length-1 && !reflect.DeepEqual(cur, tail){
            panic("cur and tail should be the same for the last step")
        }
        // move to the next one
        cur = curContentNode.Next
    }
    return content, nil
}

func (f *FileInfoNode) delete_all_content(lockbox *Lockbox) error{
    var head, cur uuid.UUID

    head = f.FileContentHead
    cur = head

    for i := 0; i < f.Length; i++{
        // Load the next node first
        encKey := lockbox.GetContentEncryptKey(i)
        hmacKey := lockbox.GetContentHMACKey(i)
        
        var curContentNode FileContentNode
        err := LoadStructFromDatastore(encKey, hmacKey, cur, &curContentNode)

        if err != nil {
            // malicious actions happen
            return err
        }
        
        // delete the current one
        userlib.DatastoreDelete(cur)
        // move to the next one
        cur = curContentNode.Next
    }

    // Reset to its default value
    f.FileContentHead = uuid.UUID{}
    f.FileContentTail = uuid.UUID{}
    f.Length = 0

    return nil
}

type FileContentNode struct {
    Next uuid.UUID
    Content []byte
}

func InitFileContentNode(content []byte) *FileContentNode{
    var fcn FileContentNode
    fcn.Content = content
    return &fcn
}

type LockboxInfo struct {
    LockboxKey []byte // the key to open(and authenticate) the lockbox
    LockboxUUID uuid.UUID
}

type Lockbox struct {
    FileKey []byte // the root key to decrypt and authenticate the file content
}

// The owner needs to tell the invitee:
// 1. where is the file start node and end node
// 2. where is the lockbox and how to open the lockbox
type Invitation struct{
    FileInfoNodeUUID uuid.UUID // {head, tail}
    LockboxInfo LockboxInfo
}

func (l *Lockbox) InitLockbox() {
    l.FileKey = userlib.RandomBytes(16)
}

func (l *Lockbox) GetEncryptKey() []byte {
    encKey, err := userlib.HashKDF(l.FileKey, []byte("encrypt"))
    if err != nil {
        panic(err)
    }
    return encKey[:16]
}

func (l *Lockbox) GetContentEncryptKey(idx int) []byte {
    encKey, err := userlib.HashKDF(l.FileKey, []byte(fmt.Sprintf("encrypt:%d", idx)))
    if err != nil {
        panic(err)
    }
    return encKey[:16]
}

func (l *Lockbox) GetHMACKey() []byte{
    hmacKey, err:= userlib.HashKDF(l.FileKey, []byte("hmac"))
    if err != nil {
        panic(err)
    }
    return hmacKey[:16]
}
func (l *Lockbox) GetContentHMACKey(idx int) []byte{
    hmacKey, err:= userlib.HashKDF(l.FileKey, []byte(fmt.Sprintf("hmac:%d", idx)))
    if err != nil {
        panic(err)
    }
    return hmacKey[:16]
}

// Get the uuid of a filename under this username's namespace
// uuid = hash(hash(username) || hash(filename))
func GetFileMetadataUUID(username string, filename string) (uuid.UUID){
    hash_username := userlib.Hash([]byte(username))
    hash_filename := userlib.Hash([]byte(filename))
    
    concat := append(hash_username, hash_filename...)

    hashed := userlib.Hash(concat)[:16]
    id, err := uuid.FromBytes(hashed)
    if err != nil {
        panic(err)
    }
    return id
}

// uuid = hash(hash(username) || hash(filename) || hash("info") || hash(numRevoked))
func GetFileInfoUUID(username string, filename string, numRevoked int) uuid.UUID{
    hash_username := userlib.Hash([]byte(username))
    hash_filename := userlib.Hash([]byte(filename))
    hash_numRevoked := userlib.Hash([]byte(fmt.Sprintf("numRevoked:%d", numRevoked)))

    concat := append(hash_username, hash_filename...)
    concat = append(concat, []byte("info")...)
    concat = append(concat, hash_numRevoked...)

    hashed := userlib.Hash(concat)[:16]
    id, err := uuid.FromBytes(hashed)
    if err != nil {
        panic(err)
    }
    return id
}

// uuid = hash(hash(username) || hash(filename) || hash("content")
//             || hash(numRevoked) || hash(index))
// Note that only the owner will revoke the invitation
// so only the owner knows how to hash the FileContentNodeUUID is acceptable
func GetFileContentNodeUUID(username string, filename string, numRevoked int, index int) (uuid.UUID){
    hash_username := userlib.Hash([]byte(username))
    hash_filename := userlib.Hash([]byte(filename))
    hash_numRevoked := userlib.Hash([]byte(fmt.Sprintf("%d", numRevoked)))
    hash_index := userlib.Hash([]byte(fmt.Sprintf("%d", index)))

    concat := append(hash_username, hash_filename...)
    concat = append(concat, hash_numRevoked...)
    concat = append(concat, hash_index...)

    hashed := userlib.Hash(concat)[:16]
    id, err := uuid.FromBytes(hashed)
    if err != nil {
        panic(err)
    }
    return id
}

// uuid = hash(hash(sender) || hash(sender_filename) || hash(recipient))
func GetInvitationUUID(
        sender string, sender_filename string, recipient string) uuid.UUID{
    hash_sender := userlib.Hash([]byte(sender))
    hash_filename := userlib.Hash([]byte(sender_filename))
    hash_recipient := userlib.Hash([]byte(recipient))

    concat := append(hash_sender, hash_filename...)
    concat = append(concat, hash_recipient...)

    hashed := userlib.Hash(concat)[:16]
    id, err := uuid.FromBytes(hashed)
    if err != nil {
        panic(err)
    }
    return id

}

func GetUserUUID(username string) (uuid.UUID){
    hashed := userlib.Hash([]byte(username))[:16]
    useruuid, err := uuid.FromBytes(hashed)
    if err != nil {
        // should not panic
        panic(err)
    }
    return useruuid
}

// UUID/PKE
func GetPublicKeyKey(username string) string{
    return GetUserUUID(username).String() + "/PKE"
}

// UUID/DS
func GetVerifyKeyKey(username string) string{
    return GetUserUUID(username).String() + "/DS"
}

func GetHMACKey(rootKey []byte) []byte{
    hmacKey, err := userlib.HashKDF(rootKey, []byte("hmac"))
    if err != nil {
        panic(err)
    }
    // 512 bits = 64 bytes
    // but for symmetric key we only need 16 bytes
    return hmacKey[:16]
}

func GetEncryptKey(rootKey []byte) []byte{
    encryptKey, err := userlib.HashKDF(rootKey, []byte("encrypt"))
    if err != nil {
        panic(err)
    }
    // 512 bits = 64 bytes
    // but for symmetric key we only need 16 bytes
    return encryptKey[:16]
}

// We need to add the filename into the HashKDF
// to prevent swapping attack
// i.e. Assume {file1: Enc(key, file1)}, {file2: Enc(key, file2)}
//      it will allow the attacker to swap two records without detection
//      For example, {file2: Enc(key, file1)}, {file1: Enc(key, file2)}
// Thus we must use {file1, Enc(key + file1, file1)}, {file2: Enc(key + file2, file2)}
func (user *User) GetFileMetadataEncryptKey(filename string) []byte{
    encryptKey, err := userlib.HashKDF(user.rootKey, []byte("encrypt" + filename))
    if err != nil {
        panic(err)
    }
    return encryptKey[:16]
}

// Same reason as GetFileMetadataEncryptKey
func (user *User) GetFileMetadataHMACKey(filename string) []byte{
    hmacKey, err := userlib.HashKDF(user.rootKey, []byte("hmac" + filename))
    if err != nil {
        panic(err)
    }
    return hmacKey[:16]
}

func (user *User) GetHMAC() []byte{
    hmacKey := GetHMACKey(user.rootKey)
    
    var serialized []byte
    serialized, err := json.Marshal(user)
    if err != nil {
        panic(err)
    }

    hmac, err := userlib.HMACEval(hmacKey, serialized)
    if err != nil{
        panic(err)
    }
    return hmac
}

// I notice that using uuid to get a struct is quite common
// NOTE: v must be a pointer type (or it will panic)
func LoadStructFromDatastore(
            encryptKey []byte, hmacKey[]byte, id uuid.UUID, v interface{}) error{
    ciphertext_and_hmac, ok := userlib.DatastoreGet(id)
    if !ok {
        return errors.New(
            fmt.Sprintf("This uuid = %v does not exist.", id))
    }
    // Decrypt
    err := CheckThenDecrypt(encryptKey, hmacKey, ciphertext_and_hmac, v)
    return err
}

func WriteToDatastoreFromStruct(
            encryptKey []byte, hmacKey []byte, id uuid.UUID, v interface{}){
    // NOTE: we just write without checking, because if someone tampered with this record
    // we just safely overwite this record
    ciphertext_and_hmac := EncryptThenMac(encryptKey, hmacKey, v)
    userlib.DatastoreSet(id, ciphertext_and_hmac)
}

// ================== Expose private variables only for debugging =============
func (user *User) PrivateKey() userlib.PKEDecKey{
    return user.privateKey
}

func (user *User) SignKey() userlib.DSSignKey{
    return user.signKey
}
// ============================================================================


// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
    if len(username) == 0 {
        return nil, errors.New("username should at least contain one character")
    }
	var userdata User

    var useruuid uuid.UUID
    useruuid = GetUserUUID(username)
    // check if there is any existing username in the datastore
    _, ok := userlib.DatastoreGet(useruuid)
    if ok {
        return nil, errors.New("This user already exists or an attacker already created this entry")
    }

    // No need to export these values
    userdata.username = username
    userdata.password = password

    userdata.ArgonSalt = userlib.RandomBytes(SaltLength)
    userdata.rootKey = userlib.Argon2Key([]byte(password), userdata.ArgonSalt, 16)

    // For password verification
    userdata.PasswordSalt = userlib.RandomBytes(SaltLength)
    userdata.HashedPassword = userlib.Argon2Key(
        []byte(password), userdata.PasswordSalt, 64)

    // ======= PKE ========
    publicKey, privateKey, err := userlib.PKEKeyGen()

    if err != nil {
        panic(err)
    }

    userdata.privateKey = privateKey
    var privateKey_bytes []byte
    privateKey_bytes, err = json.Marshal(privateKey)

    if err != nil {
        panic(err)
    }

    // Encrypt the private key
    iv := userlib.RandomBytes(userlib.AESBlockSizeBytes)
    userdata.Encrypted_privateKey = userlib.SymEnc(GetEncryptKey(userdata.rootKey), iv, privateKey_bytes)

    // Store this user's public key on the Keystore
    if err := userlib.KeystoreSet(GetPublicKeyKey(username), publicKey); err != nil{
        panic(err)
    }
    // ====================

    // ======= DS  ========
    signKey, verifyKey, err := userlib.DSKeyGen()

    if err != nil {
        panic(err)
    }

    userdata.signKey = signKey
    var signKey_bytes []byte
    signKey_bytes, err = json.Marshal(signKey)

    if err != nil {
        panic(err)
    }

    iv = userlib.RandomBytes(userlib.AESBlockSizeBytes)
    userdata.Encrypted_signKey = userlib.SymEnc(GetEncryptKey(userdata.rootKey), iv, signKey_bytes)

    if err := userlib.KeystoreSet(GetVerifyKeyKey(username), verifyKey); err != nil{
        panic(err)
    }
    // ====================

    // Generate HMAC tag

    hmac := userdata.GetHMAC()

    var serialized []byte
    serialized, err = json.Marshal(userdata)

    if err != nil {
        panic(err)
    }
    
    var data_and_hmac []byte
    data_and_hmac = append(serialized, hmac...)

    // store it in the datastore
    userlib.DatastoreSet(useruuid, data_and_hmac)

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User

    userdata.username = username
    userdata.password = password

    var useruuid uuid.UUID
    useruuid = GetUserUUID(username)

    var data_and_hmac []byte
    data_and_hmac, ok := userlib.DatastoreGet(useruuid)
    if !ok {
        return nil, errors.New("This user does not exist")
    }

    if len(data_and_hmac) < HMACLength {
        return nil, errors.New("The data_and_hmac should be at least 64 bytes (for HMAC tag)")
    }

    var serialized, hmac []byte
    serialized, hmac = data_and_hmac[:len(data_and_hmac)-HMACLength],
                        data_and_hmac[len(data_and_hmac)-HMACLength:]

    err = json.Unmarshal(serialized, &userdata)
    if err != nil {
        return nil, errors.New("The serialized json part is tampered!!!!")
    }

    if len(userdata.ArgonSalt) != SaltLength {
        return nil, errors.New("The ArgonSalt length is wrong! It must be tampered with")
    }

    // Check the integrity of this user struct
    // NOTE: we directly use the ArgonSalt because if the attacker tampered with it
    //       the hmac will directly fail
    userdata.rootKey = userlib.Argon2Key([]byte(password), userdata.ArgonSalt, 16)

    regen_hmac, err := userlib.HMACEval(GetHMACKey(userdata.rootKey), serialized)
    if err != nil {
        panic(err)
    }

    if !userlib.HMACEqual(regen_hmac, hmac) {
        return nil, errors.New(
            "This data (or ArgonSalt) is already tampered or the password provided a wrong password")
    }

    if len(userdata.PasswordSalt) != SaltLength {
        return nil, errors.New("The PasswordSalt length is wrong! It must be tampered with")
    }

    // Check the correctness of the password
    regen_hashed_password := userlib.Argon2Key([]byte(password), userdata.PasswordSalt, 64)
    for i := 0; i < 64; i++ {
        if regen_hashed_password[i] != userdata.HashedPassword[i]{
            return nil, errors.New("You provided the wrong password")
        }
    }

    // Decrypt secret stuffs
    var ciphertext []byte
    var plaintext []byte

    ciphertext = userdata.Encrypted_privateKey

    plaintext = userlib.SymDec(GetEncryptKey(userdata.rootKey), ciphertext)

    // recover the private key
    if err := json.Unmarshal(plaintext, &userdata.privateKey); err != nil{
        // should not happen because we already checked the integrity
        panic(err)
    }

    ciphertext = userdata.Encrypted_signKey
    plaintext = userlib.SymDec(GetEncryptKey(userdata.rootKey), ciphertext)

    if err := json.Unmarshal(plaintext, &userdata.signKey); err != nil {
        panic(err)
    }

	return &userdata, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {

    // Check if this file already exists
    filemetadatauuid := GetFileMetadataUUID(userdata.username, filename)

    var _ []byte
    _, ok := userlib.DatastoreGet(filemetadatauuid)

    var filemetadata *FileMetadata
    // This file does not exist, create a new FileMetadata
    if !ok {
        filemetadata = InitFileMetadata(userdata.username, filename)
        // Write to the datastore (encrypt-and-mac by user's password)
        WriteToDatastoreFromStruct(
            userdata.GetFileMetadataEncryptKey(filename),
            userdata.GetFileMetadataHMACKey(filename),
            filemetadatauuid, &filemetadata)

        // Append a node
        var fileInfoNode FileInfoNode
        err = LoadStructFromDatastore(
            filemetadata.Lockbox.GetEncryptKey(),
            filemetadata.Lockbox.GetHMACKey(),
            filemetadata.FileInfoNodeUUID, &fileInfoNode)

        if err != nil {
            // NOTE: This cannot be tested because the attacker must execute an concurrent attack
            //       during this function's execution
            return errors.New("file Info Node is tampered with by the attacker")
        }

        // Add a new node with its content
        err = fileInfoNode.append_new_node(&filemetadata.Lockbox, content)
        if err != nil{
            panic("should not happen because all we do is simply writing stuff without loading anything")
        }
        // Write the updated FileInfoNode back
        WriteToDatastoreFromStruct(
            filemetadata.Lockbox.GetEncryptKey(),
            filemetadata.Lockbox.GetHMACKey(),
            filemetadata.FileInfoNodeUUID, &fileInfoNode)
        return nil
    }

    // Load the existing filemetadata
    filemetadata = new(FileMetadata)
    err = LoadStructFromDatastore(
        userdata.GetFileMetadataEncryptKey(filename),
        userdata.GetFileMetadataHMACKey(filename),
        filemetadatauuid, filemetadata)

    if err != nil {
        return err
    }

    var fileInfoNode FileInfoNode
    if filemetadata.IsOwner {
        // Load FileInfoNode back
        err = LoadStructFromDatastore(
            filemetadata.Lockbox.GetEncryptKey(),
            filemetadata.Lockbox.GetHMACKey(),
            filemetadata.FileInfoNodeUUID, &fileInfoNode)
        if err != nil {
            return err
        }
        
        // Before overwriting all the content, we delete the existingexisting  content nodes first
        err = fileInfoNode.delete_all_content(&filemetadata.Lockbox)
        if err != nil{
            return err
        }
        // NOTE: we haven't write FileInfoNode back to the Datastore

        // Append a new node
        err = fileInfoNode.append_new_node(&filemetadata.Lockbox, content)
        if err != nil{
            panic("should not happen because all we do is simply writing stuff without loading anything")
        }

        // Write back
        WriteToDatastoreFromStruct(
            filemetadata.Lockbox.GetEncryptKey(),
            filemetadata.Lockbox.GetHMACKey(),
            filemetadata.FileInfoNodeUUID, &fileInfoNode)
    }else{
        panic("TODO")
    }

    // Otherwise, overwrite the content
    return nil
}

func (user *User) AppendToFile(filename string, content []byte) (err error) {
    filemetadatauuid := GetFileMetadataUUID(user.username, filename)

    var filemetadata FileMetadata

    err = LoadStructFromDatastore(
        user.GetFileMetadataEncryptKey(filename),
        user.GetFileMetadataHMACKey(filename),
        filemetadatauuid, &filemetadata)

    if err != nil {
        // It may be triggered by
        // * An attacker has tampered with the record
        // * This file does not exists
        return err
    }

    var lockbox *Lockbox
    var fileInfoNode FileInfoNode

    if filemetadata.IsOwner {
        lockbox = &filemetadata.Lockbox
    }else{
        panic("TODO")
    }
    
    err = LoadStructFromDatastore(
        lockbox.GetEncryptKey(),
        lockbox.GetHMACKey(),
        filemetadata.FileInfoNodeUUID, &fileInfoNode)

    if err != nil{
        // If the FileInfoNode is tampered, it will err
        return err
    }

    err = fileInfoNode.append_new_node(lockbox, content)
    if err != nil{
        return err
    }

    // Update the FileInfoNode
    WriteToDatastoreFromStruct(
        lockbox.GetEncryptKey(),
        lockbox.GetHMACKey(), filemetadata.FileInfoNodeUUID, &fileInfoNode)

	return nil
}

func (user *User) LoadFile(filename string) (content []byte, err error) {
    filemetadatauuid := GetFileMetadataUUID(user.username, filename)

    var filemetadata FileMetadata

    err = LoadStructFromDatastore(
        user.GetFileMetadataEncryptKey(filename),
        user.GetFileMetadataHMACKey(filename),
        filemetadatauuid, &filemetadata)

    if err != nil {
        // It may be triggered by
        // * An attacker has tampered with the record
        // * This file does not exists
        return nil, err
    }

    // Load the content
    if filemetadata.IsOwner{
        var fileInfoNode FileInfoNode
        err = LoadStructFromDatastore(
            filemetadata.Lockbox.GetEncryptKey(),
            filemetadata.Lockbox.GetHMACKey(),
            filemetadata.FileInfoNodeUUID, &fileInfoNode)

        if err != nil {
            return nil, err
        }
        // Load the content by traversing the linked list
        content, err = fileInfoNode.load_content(&filemetadata.Lockbox)
        if err != nil{
            return nil, err
        }
    }else{
        panic("TODO")
    }
    return content, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
