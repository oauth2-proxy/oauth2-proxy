package basic

import (
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
)

const (
	adminUser     = "admin"
	adminPassword = "Adm1n1str$t0r"
	user1         = "user1"
	user1Password = "UsErOn3P455"
	user2         = "user2"
	user2Password = "us3r2P455W0Rd!"
)

var (
	fileNames []string
)

var _ = AfterSuite(func() {
	for _, v := range fileNames {
		err := os.Remove(v)
		Expect(err).ToNot(HaveOccurred())
	}
})

var _ = Describe("HTPasswd Suite", func() {
	Context("with an HTPassword Validator", func() {
		assertHtpasswdMapFromFile := func(filePath string) {
			var htpasswd *htpasswdMap
			var err error

			BeforeEach(func() {
				var validator Validator
				validator, err = NewHTPasswdValidator(filePath)

				var ok bool
				htpasswd, ok = validator.(*htpasswdMap)
				Expect(ok).To(BeTrue())
			})

			It("does not return an error", func() {
				Expect(err).ToNot(HaveOccurred())
			})

			It("has the correct number of users", func() {
				Expect(htpasswd.users).To(HaveLen(3))
			})

			It("accepts the correct passwords", func() {
				Expect(htpasswd.Validate(adminUser, adminPassword)).To(BeTrue())
				Expect(htpasswd.Validate(user1, user1Password)).To(BeTrue())
				Expect(htpasswd.Validate(user2, user2Password)).To(BeTrue())
			})

			It("rejects incorrect passwords", func() {
				Expect(htpasswd.Validate(adminUser, "asvdfda")).To(BeFalse())
				Expect(htpasswd.Validate(user1, "BHEdgbtr")).To(BeFalse())
				Expect(htpasswd.Validate(user2, "12345")).To(BeFalse())
			})

			It("rejects a non existent user", func() {
				// Users are case sensitive
				Expect(htpasswd.Validate("ADMIN", adminPassword)).To(BeFalse())
			})
		}

		Context("load from file", func() {
			Context("with sha1 entries", func() {
				const filePath = "./test/htpasswd-sha1.txt"

				assertHtpasswdMapFromFile(filePath)
			})

			Context("with bcrypt entries", func() {
				const filePath = "./test/htpasswd-bcrypt.txt"

				assertHtpasswdMapFromFile(filePath)
			})

			Context("with mixed entries", func() {
				const filePath = "./test/htpasswd-mixed.txt"

				assertHtpasswdMapFromFile(filePath)
			})

			Context("with a non existent file", func() {
				const filePath = "./test/htpasswd-doesnt-exist.txt"
				var validator Validator
				var err error

				BeforeEach(func() {
					validator, err = NewHTPasswdValidator(filePath)
				})

				It("returns an error", func() {
					Expect(err).To(MatchError("could not load htpasswd file: could not open htpasswd file: open ./test/htpasswd-doesnt-exist.txt: no such file or directory"))
				})

				It("returns a nil validator", func() {
					Expect(validator).To(BeNil())
				})
			})

			Context("htpasswd file is updated", func() {
				const filePathPrefix = "htpasswd-file-updated-"
				const adminUserHtpasswdEntry = "admin:$2y$05$SXWrNM7ldtbRzBvUC3VXyOvUeiUcP45XPwM93P5eeGOEPIiAZmJjC"
				const user1HtpasswdEntry = "user1:$2y$05$/sZYJOk8.3Etg4V6fV7puuXfCJLmV5Q7u3xvKpjBSJUka.t2YtmmG"

				type htpasswdUpdate struct {
					testText              string
					remove                bool
					expectedLen           int
					expectedGomegaMatcher types.GomegaMatcher
				}

				assertHtpasswdMapUpdate := func(hu htpasswdUpdate) {
					var validator Validator
					var file *os.File
					var err error

					// Create a temporary file with at least one entry
					file, err = os.CreateTemp("", filePathPrefix)
					Expect(err).ToNot(HaveOccurred())
					_, err = file.WriteString(adminUserHtpasswdEntry + "\n")
					Expect(err).ToNot(HaveOccurred())

					validator, err = NewHTPasswdValidator(file.Name())
					Expect(err).ToNot(HaveOccurred())

					htpasswd, ok := validator.(*htpasswdMap)
					Expect(ok).To(BeTrue())

					if hu.remove {
						// Overwrite the original file with another entry
						err = os.WriteFile(file.Name(), []byte(user1HtpasswdEntry+"\n"), 0644)
						Expect(err).ToNot(HaveOccurred())
					} else {
						// Add another entry to the original file in append mode
						_, err = file.WriteString(user1HtpasswdEntry + "\n")
						Expect(err).ToNot(HaveOccurred())
					}

					err = file.Close()
					Expect(err).ToNot(HaveOccurred())

					fileNames = append(fileNames, file.Name())

					It("has the correct number of users", func() {
						Expect(len(htpasswd.GetUsers())).To(Equal(hu.expectedLen))
					})

					It(hu.testText, func() {
						Expect(htpasswd.Validate(adminUser, adminPassword)).To(hu.expectedGomegaMatcher)
					})

					It("new entry is present", func() {
						Expect(htpasswd.Validate(user1, user1Password)).To(BeTrue())
					})
				}

				Context("htpasswd entry is added", func() {
					assertHtpasswdMapUpdate(htpasswdUpdate{"initial entry is present", false, 2, BeTrue()})
				})

				Context("htpasswd entry is removed", func() {
					assertHtpasswdMapUpdate(htpasswdUpdate{"initial entry is removed", true, 1, BeFalse()})
				})

			})
		})
	})
})
