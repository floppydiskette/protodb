package protodb

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"regexp"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"crypto/rand"

	uuid "github.com/nu7hatch/gouuid"
)

type ProtoDB struct {
	client      *mongo.Client
	pepper      string
	email_regex *regexp.Regexp
}

const (
	email_rgx = `^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`
)

var (
	ErrInvalidPassword = errors.New("invalid password")
	ErrNoAccount       = errors.New("no account")
	ErrBadPassword     = errors.New("bad password")
	ErrBadUsername     = errors.New("bad username")
	ErrBadEmail        = errors.New("bad email")
	ErrAccountExists   = errors.New("account exists")
)

func NewProtoDB(uri string, pepper string) (*ProtoDB, error) {
	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(uri))
	if err != nil {
		return nil, err
	}

	return &ProtoDB{
		client:      client,
		pepper:      pepper,
		email_regex: regexp.MustCompile(email_rgx),
	}, nil
}

// structs

type User struct {
	User_id           string   `bson:"user_id"`
	Username          string   `bson:"username"`
	Username_lower    string   `bson:"username_lower"`
	Email             string   `bson:"email"`
	Email_verified    bool     `bson:"email_verified"`
	Password          string   `bson:"password"`
	Salt              string   `bson:"salt"`
	Creation_date     int64    `bson:"creation_date"`
	Buddy_list        []Buddy  `bson:"buddy_list"`
	Buddy_request_ids []string `bson:"buddy_request_ids"`
}

type Buddy struct {
	User_id  string `bson:"user_id"`
	Username string `bson:"username"`
	Accepted bool   `bson:"accepted"`
	Nickname string `bson:"nickname"`
}

// macro funcs

func gen_salt() string {
	bytes := make([]byte, 16) // this probably isn't the most secure, but i'm stupid and don't know how to make it better
	_, err := rand.Read(bytes)
	if err != nil {
		return ""
	}
	return string(bytes)
}

func hash_password(password string, salt string, pepper string) string {
	key := argon2.IDKey([]byte(password+pepper), []byte(salt), 20, 64*1024, 4, 64)
	// convert to base64
	return base64.StdEncoding.EncodeToString(key)
}

func is_pass_secure(password string) bool {
	if len(password) < 10 {
		return false
	} else {
		return true
	}
}

// todo: make this better
func is_username_allowed(username string) bool {
	if len(username) < 3 {
		return false
	} else if len(username) > 30 {
		return false
	} else if strings.Contains(username, " ") {
		return false
	} else {
		return true
	}
}

func is_not_malformed_email(email string, reg *regexp.Regexp) bool {
	if !reg.MatchString(email) {
		return false
	} else {
		return true
	}
}

func gen_user_id() string {
	id, err := uuid.NewV4()
	if err != nil {
		return "ERROR" // i should really handle this better
	}
	return id.String()
}

func (user *User) check_password(password string, pepper string) bool {
	// hash the password
	hash := hash_password(password, user.Salt, pepper)
	// compare the hashes
	if hash == user.Password {
		return true
	} else {
		return false
	}
}

// methods

func (db *ProtoDB) AreTheyFriends(a *User, b *User) bool {
	found_buddy := false
	for _, buddy := range a.Buddy_list {
		if buddy.User_id == b.User_id {
			found_buddy = true
			break
		}
	}
	return found_buddy
}

func (db *ProtoDB) UserExists(username string) (bool, error) {
	// get users collection
	users := db.client.Database("protoserve").Collection("users")
	// check if user exists
	count, err := users.CountDocuments(context.TODO(), bson.M{"username_lower": strings.ToLower(username)})
	if err != nil {
		return false, err
	} else {
		return count > 0, nil
	}
}

func (db *ProtoDB) GetUserByID(id string) (*User, error) {
	// get users collection
	users := db.client.Database("protoserve").Collection("users")
	// find user by id
	var result *User
	err := users.FindOne(context.TODO(), bson.M{"user_id": id}).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, ErrNoAccount
		} else {
			return nil, err
		}
	}
	return result, nil
}

func (db *ProtoDB) GetUserByUsername(username string) (*User, error) {
	// get users collection
	users := db.client.Database("protoserve").Collection("users")
	// find user by username
	var result *User
	err := users.FindOne(context.TODO(), bson.M{"username_lower": strings.ToLower(username)}).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, ErrNoAccount
		} else {
			return nil, err
		}
	}
	return result, nil
}

func (db *ProtoDB) AddBuddy(from_id string, to_username string) error {
	// query username to make sure it exists
	to_exists, err := db.UserExists(to_username)
	if err != nil {
		return err
	} else if to_exists == false {
		return ErrNoAccount
	}
	// check if to_username is awaiting a request acceptance
	// if so, accept it
	// if not, add to_username to from_username's buddy list
	// if from_username is already on to_username's buddy list, do nothing
	to_user, err := db.GetUserByUsername(to_username)
	if err != nil {
		return err
	}
	for _, buddy := range to_user.Buddy_list {
		if buddy.User_id == from_id {
			// is waiting for acceptance?
			if buddy.Accepted == false {
				// accept request
				buddy.Accepted = true
				// update user
				_, err := db.client.Database("protoserve").Collection("users").UpdateOne(context.TODO(), bson.M{"user_id": to_user.User_id}, bson.M{"$set": bson.M{"buddy_list": to_user.Buddy_list}})
				if err != nil {
					return err
				}
				return nil
			} else {
				// already on buddy list
				return ErrAccountExists
			}
		}
	}
	// add to_username to from_username's buddy list
	from_user, err := db.GetUserByID(from_id)
	if err != nil {
		return err
	}
	from_user.Buddy_list = append(from_user.Buddy_list, Buddy{from_user.User_id, from_user.Username, false, ""})
	// update user
	_, err = db.client.Database("protoserve").Collection("users").UpdateOne(context.TODO(), bson.M{"user_id": from_user.User_id}, bson.M{"$set": bson.M{"buddy_list": from_user.Buddy_list}})
	if err != nil {
		return err
	}
	// add from_username's id to to_username's buddy request list
	to_user.Buddy_request_ids = append(to_user.Buddy_request_ids, from_user.User_id)
	// update user
	_, err = db.client.Database("protoserve").Collection("users").UpdateOne(context.TODO(), bson.M{"user_id": to_user.User_id}, bson.M{"$set": bson.M{"buddy_request_ids": to_user.Buddy_request_ids}})
	if err != nil {
		return err
	}
	return nil
}

func (db *ProtoDB) RemoveBuddy(from_id string, to_username string) error {
	// query username to make sure it exists
	to_exists, err := db.UserExists(to_username)
	if err != nil {
		return err
	} else if to_exists == false {
		return ErrNoAccount
	}
	// check if to_username is on from_username's buddy list
	// if so, remove from_username from to_username's buddy list
	// if not, do nothing
	to_user, err := db.GetUserByUsername(to_username)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return ErrNoAccount
		} else {
			return err
		}
	}
	for i, buddy := range to_user.Buddy_list {
		if buddy.User_id == from_id {
			// remove from buddy list
			to_user.Buddy_list = append(to_user.Buddy_list[:i], to_user.Buddy_list[i+1:]...)
			// update user
			_, err := db.client.Database("protoserve").Collection("users").UpdateOne(context.TODO(), bson.M{"user_id": to_user.User_id}, bson.M{"$set": bson.M{"buddy_list": to_user.Buddy_list}})
			if err != nil {
				return err
			}
			return nil
		}
	}
	// not on buddy list
	return ErrNoAccount
}

func (db *ProtoDB) QueryBuddyList(user_id string, requests_instead bool) ([]Buddy, []string, error) {
	// get users collection
	users := db.client.Database("protoserve").Collection("users")
	// find user by id
	var result *User
	err := users.FindOne(context.TODO(), bson.M{"user_id": user_id}).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil, ErrNoAccount
		} else {
			return nil, nil, err
		}
	}
	if requests_instead {
		return nil, result.Buddy_request_ids, nil
	} else {
		return result.Buddy_list, nil, nil
	}
}

func (db *ProtoDB) RegisterUser(username string, password string, email string) error {
	// check if user exists
	exists, err := db.UserExists(username)
	if err != nil {
		return err
	} else if exists {
		return ErrAccountExists
	} else {
		// check if password is secure
		if !is_pass_secure(password) {
			return ErrBadPassword
		}
		// check if username is allowed
		if !is_username_allowed(username) {
			return ErrBadUsername
		}
		// check if email is allowed
		fmt.Println(email)
		if !is_not_malformed_email(email, db.email_regex) {
			return ErrBadEmail
		}

		// create user
		salt := gen_salt()

		user := &User{
			User_id:           gen_user_id(),
			Username:          username,
			Username_lower:    strings.ToLower(username),
			Email:             email,
			Email_verified:    true, // todo: make this false once email verification is implemented
			Password:          hash_password(password, salt, db.pepper),
			Salt:              salt,
			Creation_date:     time.Now().Unix(),
			Buddy_list:        []Buddy{},
			Buddy_request_ids: []string{},
		}
		// insert user
		users := db.client.Database("protoserve").Collection("users")
		_, err := users.InsertOne(context.TODO(), user)
		if err != nil {
			return err
		} else {
			return nil
		}
	}
}

func (db *ProtoDB) LoginUser(username string, password string) (string, error) {
	// get users collection
	users := db.client.Database("protoserve").Collection("users")
	// check if user exists
	var user User
	err := users.FindOne(context.TODO(), bson.M{"username_lower": strings.ToLower(username)}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return "", ErrNoAccount
		} else {
			return "", err
		}
	} else {
		// check if password is correct
		if user.check_password(password, db.pepper) {
			return user.User_id, nil
		} else {
			return "", ErrInvalidPassword
		}
	}
}
