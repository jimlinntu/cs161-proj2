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
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
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

// type FileMetadata struct {
//     FileContentHead uuid.UUID
//     FileContentTail uuid.UUID
//     FileKey []byte
//     // each we revoke a user we should change the file location by adding this number into
//     // the hash function
//     NumRevoked int
//     // record our direct shared users (a.k.a children in the shared tree)
//     SharedUsers []string 
// }


// type FileContentNode struct {
//     NextFileContentUUID uuid.UUID
//     Content []byte
// }

func GetUserUUID(username string) (uuid.UUID){
    hashed := userlib.Hash([]byte(username))[:16]
    useruuid, err := uuid.FromBytes(hashed)
    if err != nil {
        // should not panic
        panic(err)
    }
    return useruuid
}

// Ex. "Alice://myfile#0#"
// func getFileUUID(username string, filename string, counter int, numRevoked int) (uuid.UUID, error){
//     s := fmt.Sprintf("%s://%s#%d", username, filename, counter)
//     hashed := userlib.Hash([]byte(s))[:16]
//     fuuid, err := uuid.FromBytes(hashed)
//     return fuuid, err
// }

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

    // Decrpyt secret stuffs
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
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.username))[:16])
	if err != nil {
		return err
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, contentBytes)
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.username))[:16])
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	err = json.Unmarshal(dataJSON, &content)
	return content, err
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
