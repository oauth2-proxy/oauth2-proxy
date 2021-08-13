package basic

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
)

type HtpasswdValidatorTest struct {
	usersFileName string
	done              chan bool
	updateSeen        bool
}

func NewHtpasswdValidatorTest(t *testing.T) *HtpasswdValidatorTest {
	vt := &HtpasswdValidatorTest{}
	var err error
	f, err := ioutil.TempFile("", "test_users_")
	if err != nil {
		t.Fatalf("failed to create htpasswd temp file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close htpasswd temp file: %v", err)
	}
	vt.usersFileName = f.Name()
	vt.done = make(chan bool, 1)
	return vt
}

func (vt *HtpasswdValidatorTest) TearDown() {
	vt.done <- true
	os.Remove(vt.usersFileName)
}

func (vt *HtpasswdValidatorTest) NewHtpasswdValidator(
	updated chan<- bool) func(string, string) bool {
	return newHTPasswdValidatorImpl(vt.usersFileName,
		vt.done, func() {
			if vt.updateSeen == false {
				updated <- true
				vt.updateSeen = true
			}
		})
}

func (vt *HtpasswdValidatorTest) WriteUsers(t *testing.T, users []string) {
	f, err := os.OpenFile(vt.usersFileName, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("failed to open auth email file: %v", err)
	}

	if _, err := f.WriteString(strings.Join(users, "\n")); err != nil {
		t.Fatalf("failed to write users to auth email file: %v", err)
	}

	if err := f.Close(); err != nil {
		t.Fatalf("failed to close auth email file: %v", err)
	}
}

func TestHtpasswdValidatorOverwriteUsersListDirectly(t *testing.T) {
	testCasesPreUpdate := []struct {
		name          string
		user          string
		password      string
		expectedAuthZ bool
	}{
		{
			name:          "FirstUserInListBcrypt",
			user:          "admin",
			password:      "Adm1n1str$t0r",
			expectedAuthZ: true,
		},
		{
			name:          "SecondUserInListBcrypt",
			user:          "user1",
			password:      "UsErOn3P455",
			expectedAuthZ: true,
		},
		{
			name:          "ThirdUserInListSHA1",
			user:          "admin1",
			password:      "Adm1n1str$t0r",
			expectedAuthZ: true,
		},
		{
			name:          "UserNotInList",
			user:          "user",
			password:      "wrongpass",
			expectedAuthZ: false,
		},
	}
	testCasesPostUpdate := []struct {
		name          string
		user          string
		password      string
		expectedAuthZ bool
	}{
		{
			name:          "retainedInList",
			user:          "admin",
			password:      "Adm1n1str$t0r",
			expectedAuthZ: true,
		},
		{
			name:          "userStillNotInTheList",
			user:          "user",
			password:      "wrongpass",
			expectedAuthZ: false,
		},
		{
			name:          "userAddedToList",
			user:          "user2",
			password:      "us3r2P455W0Rd!",
			expectedAuthZ: true,
		},
		{
			name:          "userIsCaseSensitive",
			user:          "Admin",
			password:      "Adm1n1str$t0r",
			expectedAuthZ: false,
		},
	}

	vt := NewHtpasswdValidatorTest(t)
	defer vt.TearDown()

	vt.WriteUsers(t, []string{
		//bcrypt admin:Adm1n1str$t0r
		"admin:$2y$05$SXWrNM7ldtbRzBvUC3VXyOvUeiUcP45XPwM93P5eeGOEPIiAZmJjC",
		//bcrypt user1:UsErOn3P455 
		"user1:$2y$05$/sZYJOk8.3Etg4V6fV7puuXfCJLmV5Q7u3xvKpjBSJUka.t2YtmmG",
		//SHA1 admin1:Adm1n1str$t0r
		"admin1:{SHA}gXQeRH0bcaCfhAk2gOLm1uaePMA=",
	})
	updated := make(chan bool)
	validator := vt.NewHtpasswdValidator(updated)

	for _, tc := range testCasesPreUpdate {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			authorized := validator(tc.user, tc.password)
			g.Expect(authorized).To(Equal(tc.expectedAuthZ))
		})
	}

	vt.WriteUsers(t, []string{
		//bcrypt admin:Adm1n1str$t0r
		"admin:$2y$05$SXWrNM7ldtbRzBvUC3VXyOvUeiUcP45XPwM93P5eeGOEPIiAZmJjC",
		//bcrypt user2:us3r2P455W0Rd!
		"user2:$2y$05$l22MubgKTZFTjTs8TNg5k.YKvcnM2.bA/.iwl0idef5CbekdvBxva",
		//SHA1 user3:us3r2P455W0Rd!
		"user3:{SHA}MoN9/JCJEcYUb6GCQ+2buDvn9pI=",
	})
	<-updated

	for _, tc := range testCasesPostUpdate {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			authorized := validator(tc.user, tc.password)
			g.Expect(authorized).To(Equal(tc.expectedAuthZ))
		})
	}
}