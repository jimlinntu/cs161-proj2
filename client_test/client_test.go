package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
    "fmt"
    "encoding/json"
    "reflect"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

const defaultUsername = "jim"
const usernameTwo = "andy"
const usernameThree = "candy"

const filenameOne = "test1"
const filenameTwo = "test2"
const filenameThree = "test3"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	// var alicePhone *client.User
	// var aliceLaptop *client.User
	// var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	// bobFile := "bobFile.txt"
	// charlesFile := "charlesFile.txt"
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			_, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			_, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

        Specify("Acccount Testing: Type the wrong password", func(){
            userlib.DebugMsg("Initialize Jim")
            _, err = client.InitUser("Jim", defaultPassword)
            Expect(err).To(BeNil())

            userlib.DebugMsg("Type the wrong password")
            _, err = client.GetUser("Jim", defaultPassword + "wrong")
            userlib.DebugMsg(fmt.Sprint(err))
            Expect(err).ToNot(BeNil())

        })

        Specify("Account Testing: Create an already exist account", func(){
            jimuuid := client.GetUserUUID("Jim")
            userlib.DatastoreSet(jimuuid, []byte{})

            userlib.DebugMsg("Get an existing account")
            _, err = client.InitUser("Jim", defaultPassword)
            userlib.DebugMsg(fmt.Sprint(err))
            Expect(err).ToNot(BeNil())
        })

        Specify("Account Testing: Tampering", func(){
            userlib.DebugMsg("Initialize Jim")
            _, err = client.InitUser("Jim", defaultPassword)
            Expect(err).To(BeNil())

            userlib.DebugMsg("Tampered with the ArgonSalt")
            // Directly interact with the datastore
            jimuuid := client.GetUserUUID("Jim")
            data_and_hmac, ok := userlib.DatastoreGet(jimuuid)
            if !ok {
                panic("Should not happen")
            }
            serialized, hmac := data_and_hmac[:len(data_and_hmac)-client.HMACLength],
                                data_and_hmac[len(data_and_hmac)-client.HMACLength:]

            var tmpUser client.User

            err = json.Unmarshal(serialized, &tmpUser)
            if err != nil{
                panic(err)
            }
            // Tampered with the ArgonSalt
            tmpUser.ArgonSalt = userlib.RandomBytes(client.SaltLength)

            // Seralized the tampered data
            tampered_serialized, err := json.Marshal(tmpUser)
            if err != nil{
                panic(err)
            }
            data_and_hmac = append(tampered_serialized,
                            hmac...)
            userlib.DatastoreSet(jimuuid, data_and_hmac)

            userlib.DebugMsg("Try to Get a user that is tampered with")
            _, err = client.GetUser("Jim", defaultPassword)
            userlib.DebugMsg(fmt.Sprint(err))
            Expect(err).ToNot(BeNil())

            userlib.DebugMsg("Mess up the JSON format")
            
            tampered_serialized = serialized[10:]

            data_and_hmac = append(tampered_serialized, hmac...)
            userlib.DatastoreSet(jimuuid, data_and_hmac)

            userlib.DebugMsg("Try to Get a user that its JSON is messed up")

            _, err = client.GetUser("Jim", defaultPassword)
            userlib.DebugMsg(fmt.Sprint(err))
            Expect(err).ToNot(BeNil())

            userlib.DatastoreDelete(jimuuid)
            userlib.DebugMsg("Try to Get a user that its record is deleted")
            
            _, err = client.GetUser("Jim", defaultPassword)
            userlib.DebugMsg(fmt.Sprint(err))
            Expect(err).ToNot(BeNil())

            userlib.DatastoreSet(jimuuid, []byte("too few bytes"))

            userlib.DebugMsg("Try to Get a user that its data length is shorter than HMACLength")

            _, err = client.GetUser("Jim", defaultPassword)
            userlib.DebugMsg(fmt.Sprint(err))
            Expect(err).ToNot(BeNil())

        })

        Specify("Account Testing: Get a nonexistent account", func(){
            userlib.DebugMsg("Try to get a nonexistent account")
            _, err := client.GetUser("Jim", defaultPassword)
            userlib.DebugMsg(fmt.Sprint(err))
            Expect(err).ToNot(BeNil())
        })

        Specify("Account Testing: Deny empty string username", func(){
            userlib.DebugMsg("Try to create an account with empty username")
            _, err := client.InitUser("", defaultPassword)
            userlib.DebugMsg(fmt.Sprint(err))
            Expect(err).ToNot(BeNil())
        })

        Specify("Account Testing: Check private key is recovered successfully", func(){
            jimuser, err := client.InitUser("Jim", defaultPassword)
            Expect(err).To(BeNil())

            jimuser2, err := client.GetUser("Jim", defaultPassword)
            Expect(err).To(BeNil())

            // Compare whether their privatekey types' bytes are the same

            var left, right []byte

            privateKey := jimuser.PrivateKey()
            privateKey2 := jimuser2.PrivateKey()

            left, err = json.Marshal(privateKey)
            if err != nil {
                panic(err)
            }
            right, err = json.Marshal(privateKey2)
            if err != nil {
                panic(err)
            }

            userlib.DebugMsg("Compare the initial private key and the recovered one")
            eq := reflect.DeepEqual(left, right)
            Expect(eq).To(BeTrue())

            signKey := jimuser.SignKey()
            signKey2 := jimuser2.SignKey()

            left, err = json.Marshal(signKey)
            if err != nil {
                panic(err)
            }

            right, err = json.Marshal(signKey2)
            if err != nil {
                panic(err)
            }

            // sign key should be the same
            userlib.DebugMsg("Compare the initial sign key and the recovered one")
            eq = reflect.DeepEqual(left, right)
            Expect(eq).To(BeTrue())
        })

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

        Specify("File handling: Test Owner Store and Load without tampering happening", func(){
            jimuser, err := client.InitUser("jim", defaultPassword)
            Expect(err).To(BeNil())

            userlib.DebugMsg("Create a file")
            err = jimuser.StoreFile(filenameOne, []byte(contentOne))

            Expect(err).To(BeNil())

            userlib.DebugMsg("Load a nonexistent file")
            _, err = jimuser.LoadFile(filenameTwo)

            Expect(err).ToNot(BeNil())

            userlib.DebugMsg("Load an untampered file")
            content, err := jimuser.LoadFile(filenameOne)

            Expect(err).To(BeNil())
            Expect(content).To(Equal([]byte(contentOne)))

            userlib.DebugMsg("Rewrite a file")
            err = jimuser.StoreFile(filenameOne, []byte(contentTwo))

            Expect(err).To(BeNil())

            userlib.DebugMsg("Load a rewritten file")
            content, err = jimuser.LoadFile(filenameOne)

            Expect(err).To(BeNil())
            Expect(content).To(Equal([]byte(contentTwo)))
        })

        Specify("File handling: Test multiple sessions for Store and Load", func(){
            var jimuser, jimuser2, jimuser3 *client.User

            jimuser, err = client.InitUser(defaultUsername, defaultPassword)
            Expect(err).To(BeNil())

            jimuser2, err = client.GetUser(defaultUsername, defaultPassword)
            Expect(err).To(BeNil())

            jimuser3, err = client.GetUser(defaultUsername, defaultPassword)
            
            Expect(err).To(BeNil())

            userlib.DebugMsg("User session 2 created a file")
            err = jimuser2.StoreFile(filenameOne, []byte(contentTwo))
            Expect(err).To(BeNil())

            userlib.DebugMsg("User session 1 load that file")
            content, err := jimuser.LoadFile(filenameOne)
            Expect(err).To(BeNil())
            Expect(content).To(Equal([]byte(contentTwo)))

            userlib.DebugMsg("User session 3 load that file")
            content, err = jimuser3.LoadFile(filenameOne)
            Expect(err).To(BeNil())
            Expect(content).To(Equal([]byte(contentTwo)))
            
        })

        Specify("File handling: Test Append (wo attackers tampering)", func(){
            user, err := client.InitUser(defaultUsername, defaultPassword)

            userlib.DebugMsg("Append to a nonexistent file")
            err = user.AppendToFile(filenameOne, []byte(contentOne))
            Expect(err).ToNot(BeNil())

            err = user.StoreFile(filenameOne, []byte(contentOne))
            Expect(err).To(BeNil())

            userlib.DebugMsg("Append to an existing file")

            err = user.AppendToFile(filenameOne, []byte(contentTwo))
            Expect(err).To(BeNil())

            err = user.AppendToFile(filenameOne, []byte(contentThree))
            Expect(err).To(BeNil())

            userlib.DebugMsg("Load the appended file")

            content, err := user.LoadFile(filenameOne)
            Expect(err).To(BeNil())
            Expect(content).To(Equal([]byte(contentOne + contentTwo + contentThree)))
        })

        // Specify("File handling: Test Owner Store when an attacker is present", func(){
        //     jimuser, err := client.InitUser("jim", defaultPassword)
        // })

        Specify("Test CreateInvitation", func(){
            user, err := client.InitUser(defaultUsername, defaultPassword)
            Expect(err).To(BeNil())
            _, err = client.InitUser(usernameTwo, defaultPassword)
            Expect(err).To(BeNil())

            userlib.DebugMsg("Create an invitation on a nonexistent file")
            _, err = user.CreateInvitation(filenameOne, usernameTwo)
            userlib.DebugMsg(fmt.Sprint(err))
            Expect(err).ToNot(BeNil())

            userlib.DebugMsg("Create an invitation for a nonexistent user")
            err = user.StoreFile(filenameOne, []byte(contentOne))
            Expect(err).To(BeNil())
            _, err = user.CreateInvitation(filenameOne, usernameThree)
            userlib.DebugMsg(fmt.Sprint(err))
            Expect(err).ToNot(BeNil())


            userlib.DebugMsg("Create an invitation to a user")
            _, err = user.CreateInvitation(filenameOne, usernameTwo)
            Expect(err).To(BeNil())

            userlib.DebugMsg("Reshare an invitation to a same user (expecting a panic)")
            Expect(func(){
                user.CreateInvitation(filenameOne, usernameTwo)
            }).To(Panic())
        })

        Specify("Test Create and Accept Invitations wo an attacker", func(){
            user, err := client.InitUser(defaultUsername, defaultPassword)
            Expect(err).To(BeNil())
            user2, err := client.InitUser(usernameTwo, defaultPassword)
            Expect(err).To(BeNil())

            err = user.StoreFile(filenameOne, []byte(contentOne))
            Expect(err).To(BeNil())

            userlib.DebugMsg("Create and then accept the invitation")
            invPtr, err := user.CreateInvitation(filenameOne, usernameTwo)
            Expect(err).To(BeNil())

            err = user2.AcceptInvitation(defaultUsername, invPtr, filenameTwo)
            Expect(err).To(BeNil())

            userlib.DebugMsg("Accept an invitation from a nonexistent user")
            err = user2.AcceptInvitation(usernameThree, invPtr, filenameTwo)
            userlib.DebugMsg(err.Error())
            Expect(err).ToNot(BeNil())
        })

        Specify("Test Create and Accept Invitations and manipulate the files (wo an attacker)", func(){
            user, err := client.InitUser(defaultUsername, defaultPassword)
            Expect(err).To(BeNil())
            user2, err := client.InitUser(usernameTwo, defaultPassword)
            Expect(err).To(BeNil())
            user3, err := client.InitUser(usernameThree, defaultPassword)
            Expect(err).To(BeNil())

            err = user.StoreFile(filenameOne, []byte(contentOne))
            Expect(err).To(BeNil())

            invPtr, err := user.CreateInvitation(filenameOne, usernameTwo)
            Expect(err).To(BeNil())

            userlib.DebugMsg("Load a file before sharing")
            _, err = user2.LoadFile(filenameOne)
            Expect(err).ToNot(BeNil())
            _, err = user2.LoadFile(filenameTwo)
            Expect(err).ToNot(BeNil())

            err = user2.StoreFile(filenameTwo, []byte(contentOne))
            Expect(err).To(BeNil())

            userlib.DebugMsg("Accept a file with an already used filename")
            err = user2.AcceptInvitation(defaultUsername, invPtr, filenameTwo)
            userlib.DebugMsg(err.Error())
            Expect(err).ToNot(BeNil())

            userlib.DebugMsg("Accept a file")
            err = user2.AcceptInvitation(defaultUsername, invPtr, filenameThree)
            Expect(err).To(BeNil())

            userlib.DebugMsg("Load a file not owned by me")
            content, err := user2.LoadFile(filenameThree)
            Expect(err).To(BeNil())
            Expect(content).To(Equal([]byte(contentOne)))

            userlib.DebugMsg("user2 append a content. Test if user1 can see that change")

            err = user2.AppendToFile(filenameThree, []byte(contentThree))
            Expect(err).To(BeNil())

            content, err = user.LoadFile(filenameOne)
            Expect(err).To(BeNil())
            Expect(content).To(Equal([]byte(contentOne + contentThree)))

            userlib.DebugMsg("user1 append a content. Test if user2 can see that change")

            err = user.AppendToFile(filenameOne, []byte(contentTwo))
            Expect(err).To(BeNil())

            content, err = user2.LoadFile(filenameThree)
            Expect(err).To(BeNil())
            Expect(content).To(Equal([]byte(contentOne + contentThree + contentTwo)))

            userlib.DebugMsg("user2 overwrites the file. Test if user1 can see the change")

            err = user2.StoreFile(filenameThree, []byte(contentTwo))
            Expect(err).To(BeNil())

            content, err = user.LoadFile(filenameOne)
            Expect(err).To(BeNil())
            Expect(content).To(Equal([]byte(contentTwo)))

            userlib.DebugMsg("user2 share a file with user3")
            invPtr, err = user2.CreateInvitation(filenameThree, usernameThree)
            Expect(err).To(BeNil())
            err = user3.AcceptInvitation(usernameTwo, invPtr, filenameOne)
            Expect(err).To(BeNil())

            userlib.DebugMsg("user3 changes the file. user1,2 should be able to see it")
            err = user3.AppendToFile(filenameOne, []byte(contentThree))
            Expect(err).To(BeNil())

            content, err = user.LoadFile(filenameOne)
            Expect(err).To(BeNil())
            Expect(content).To(Equal([]byte(contentTwo + contentThree)))

            content, err = user2.LoadFile(filenameThree)
            Expect(err).To(BeNil())
            Expect(content).To(Equal([]byte(contentTwo + contentThree)))
        })

        Specify("Test Create and Accept Invitations w an active attacker", func(){
            user, err := client.InitUser(defaultUsername, defaultPassword)
            Expect(err).To(BeNil())

            user2, err := client.InitUser(usernameTwo, defaultPassword)
            Expect(err).To(BeNil())

            err = user.StoreFile(filenameOne, []byte(contentOne))
            Expect(err).To(BeNil())

            invPtr, err := user.CreateInvitation(filenameOne, usernameTwo)

            userlib.DebugMsg("Tamper with the invitation record")
            userlib.DatastoreSet(invPtr, userlib.RandomBytes(100))

            err = user2.AcceptInvitation(defaultUsername, invPtr, filenameTwo)
            userlib.DebugMsg(err.Error())
            Expect(err).ToNot(BeNil())

            userlib.DebugMsg("Tamper with the invitation record")
            userlib.DatastoreSet(invPtr, userlib.RandomBytes(1000))

            err = user2.AcceptInvitation(defaultUsername, invPtr, filenameTwo)
            userlib.DebugMsg(err.Error())
            Expect(err).ToNot(BeNil())

            userlib.DebugMsg("Tamper with the filemetadata")
            userlib.DatastoreSet(
                client.GetFileMetadataUUID(defaultUsername, filenameOne),
                userlib.RandomBytes(100))

            _, err = user.CreateInvitation(filenameOne, usernameTwo)
            userlib.DebugMsg(err.Error())
            Expect(err).ToNot(BeNil())
        })

        /*
		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})
        */

        /*
		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})
        */

        Specify("Test Revoke wo an active attacker", func(){
            alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

            bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

            charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

            doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

            err = alice.StoreFile(filenameOne, []byte(contentOne))
			Expect(err).To(BeNil())

            userlib.DebugMsg(`
Build a sharing tree:
alice -> bob -> charles
      -> doris
`)
            invPtr, err := alice.CreateInvitation(filenameOne, bob.Username())
			Expect(err).To(BeNil())

            err = bob.AcceptInvitation(alice.Username(), invPtr, bob.Username())
			Expect(err).To(BeNil())

            invPtr, err = alice.CreateInvitation(filenameOne, doris.Username())
			Expect(err).To(BeNil())
            
            err = doris.AcceptInvitation(alice.Username(), invPtr, doris.Username())
			Expect(err).To(BeNil())

            invPtr, err = bob.CreateInvitation(bob.Username(), charles.Username())
			Expect(err).To(BeNil())

            err = charles.AcceptInvitation(bob.Username(), invPtr, charles.Username())
			Expect(err).To(BeNil())

            err = alice.AppendToFile(filenameOne, []byte(contentTwo))
			Expect(err).To(BeNil())

            userlib.DebugMsg("Test charles can see alice's change")
            content, err := charles.LoadFile(charles.Username())
			Expect(err).To(BeNil())
            Expect(content).To(Equal([]byte(contentOne + contentTwo)))

            err = alice.RevokeAccess(filenameOne, bob.Username())
			Expect(err).To(BeNil())

            userlib.DebugMsg("Revoke bob's sharing should disable bob to manipulate the file")
            err = bob.AppendToFile(bob.Username(), []byte("blabla"))
            userlib.DebugMsg(err.Error())
			Expect(err).ToNot(BeNil())

            userlib.DebugMsg("Revoke bob's sharing should disable charles to manipulate the file")
            _, err = charles.LoadFile(charles.Username())
            userlib.DebugMsg(err.Error())
			Expect(err).ToNot(BeNil())

            userlib.DebugMsg("While doris should still be able to see the file")
            content, err = doris.LoadFile(doris.Username())
			Expect(err).To(BeNil())
            Expect(content).To(Equal([]byte(contentOne + contentTwo)))
            userlib.DebugMsg("And doris should also be able to see the change of file")

            err = alice.AppendToFile(filenameOne, []byte(contentThree))
			Expect(err).To(BeNil())
            content, err = doris.LoadFile(doris.Username())
			Expect(err).To(BeNil())
            Expect(content).To(Equal([]byte(contentOne + contentTwo + contentThree)))
        })

	})
})
