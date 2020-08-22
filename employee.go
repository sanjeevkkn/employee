package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gopkg.in/validator.v2"

	"github.com/twinj/uuid"
	"go.mongodb.org/mongo-driver/bson/primitive"

	jwt "github.com/dgrijalva/jwt-go"
	redis "github.com/go-redis/redis/v8"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	AccessUuid   string
	RefreshUuid  string
	AtExpires    int64
	RtExpires    int64
}
type Employee struct {
	EmployeeId string `bson:"_id,omitempty" json:"employeeId"`
	Name       string `bson:"name,omitempty json:"name" validate:"min=1,max=16 regexp=^[a-zA-Z]*$"`
	Skills     string `bson:"skills" json:"skills"`
	Address    string `bson:"address" json:"address"`
	Department string `bson:"department" json:"department"`
	Active     bool   `bson :"active"`
	Password   string `bson:"password" json:"password" validate:"min=8,max=12 regexp=^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])(?=.{8,})" `
}
type EmployeeDetails struct {
	EmployeeId string `bson:"_id,omitempty" json:"employeeId"`
	Name       string `bson:"name,omitempty json:"name" validate:"min=1,max=16 regexp=^[a-zA-Z]*$"`
	Skills     string `bson:"skills" json:"skills"`
	Address    string `bson:"address" json:"address"`
	Department string `bson:"department" json:"department"`
}
type AccessDetails struct {
	AccessUuid string
	UserId     string
}

var client *redis.Client
var collection *mongo.Collection
var ctx = context.Background()

func init() {
	//Initializing redis
	dsn := os.Getenv("REDIS_DSN")
	if len(dsn) == 0 {
		dsn = "localhost:6379"
	}
	client = redis.NewClient(&redis.Options{
		Addr: dsn, //redis port

	})
	_, err := client.Ping(ctx).Result()
	if err != nil {
		panic(err)
	}
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")

	// Connect to MongoDB
	client1, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	// Check the connection
	err = client1.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Connected to MongoDB!")

	// Get a handle for your collection
	collection = client1.Database("test").Collection("Employee")

}
func ListHandler(c *gin.Context) {
	var results []*EmployeeDetails
	filter := map[string]string{}
	filters := bson.M{}
	//compare the user from the request, with the one we defined:
	// findOptions := options.Find()
	filter["department"] = c.DefaultQuery("department", "NA")
	filter["name"] = c.DefaultQuery("name", "NA")
	filter["_id"] = c.DefaultQuery("id", "NA")
	bsonMap := []bson.M{}
	projection := bson.D{
		{"_id", 1},
		{"department", 1},
		{"skills", 1},
		{"address", 1},
		{"name", 1},
	}

	for k, v := range filter {
		if v != "NA" {
			bsonMap = append(bsonMap, bson.M{k: v})
		}

	}

	if len(bsonMap) > 0 {
		filters = bson.M{"active": true, "$and": bsonMap}
	} else {
		filters = bson.M{"active": true}
	}

	cur, err := collection.Find(context.TODO(), filters, options.Find().SetProjection(projection))
	if err != nil {
		c.JSON(500, gin.H{
			"status":  "Failure",
			"message": "Error while fetching Data from mongoDB",
		})
		return

	}

	// Iterate through the cursor
	for cur.Next(context.TODO()) {
		var elem EmployeeDetails
		err := cur.Decode(&elem)
		if err != nil {
			log.Fatal(err)
		}

		results = append(results, &elem)
	}

	if err := cur.Err(); err != nil {
		log.Fatal(err)
	}

	// Close the cursor once finished
	cur.Close(context.TODO())

	fmt.Printf("Found multiple documents (array of pointers): %+v\n", results)

	c.JSON(http.StatusOK, results)

}
func CreateAuth(userid string, td *TokenDetails) error {

	at := time.Unix(td.AtExpires, 0) //converting Unix to UTC(to Time object)
	rt := time.Unix(td.RtExpires, 0)
	fmt.Println(at)

	fmt.Println(rt)
	errAccess := client.Set(ctx, td.AccessUuid, userid, 0).Err()
	if errAccess != nil {
		fmt.Println("error1")
		return errAccess
	}
	errRefresh := client.Set(ctx, td.RefreshUuid, userid, 0).Err()
	if errRefresh != nil {
		fmt.Println("error2")
		return errRefresh
	}
	errExp := client.ExpireAt(ctx, td.AccessUuid, at).Err()
	if errExp != nil {
		fmt.Println("error3")
		return errExp
	}
	errRef := client.ExpireAt(ctx, td.RefreshUuid, rt).Err()
	if errExp != nil {
		fmt.Println("error3")
		return errRef
	}
	return nil
}
func ExtractToken(r *http.Request) string {
	bearToken := r.Header.Get("Authorization")
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		fmt.Println(strArr[1])
		return strArr[1]

	}
	return ""
}
func CreateToken(userid string) (*TokenDetails, error) {
	td := &TokenDetails{}
	td.AtExpires = time.Now().Add(time.Minute * 30).Unix()
	td.AccessUuid = uuid.NewV4().String()

	td.RtExpires = time.Now().Add(time.Hour * 24 * 7).Unix()
	td.RefreshUuid = uuid.NewV4().String()

	var err error
	//Creating Access Token
	os.Setenv("ACCESS_SECRET", "jdnfksdmfksd") //this should be in an env file
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["access_uuid"] = td.AccessUuid
	atClaims["user_id"] = userid
	atClaims["exp"] = td.AtExpires
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken, err = at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return nil, err
	}
	//Creating Refresh Token
	os.Setenv("REFRESH_SECRET", "mcmvmkmsdnfsdmfdsjf") //this should be in an env file
	rtClaims := jwt.MapClaims{}
	rtClaims["refresh_uuid"] = td.RefreshUuid
	rtClaims["user_id"] = userid
	rtClaims["exp"] = td.RtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(os.Getenv("REFRESH_SECRET")))
	if err != nil {
		return nil, err
	}
	return td, nil
}

// Parse, validate, and return a token.
// keyFunc will receive the parsed token and should return the key for validating.
func VerifyToken(r *http.Request) (*jwt.Token, error) {
	tokenString := ExtractToken(r)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("ACCESS_SECRET")), nil
	})
	if err != nil {
		return nil, err
	}
	fmt.Println(tokenString)
	return token, nil
}

func TokenValid(r *http.Request) error {
	token, err := VerifyToken(r)
	if err != nil {
		return err
	}
	if _, ok := token.Claims.(jwt.Claims); !ok || !token.Valid {
		return err
	}
	return nil
}

func ExtractTokenMetadata(r *http.Request) (*AccessDetails, error) {

	token, err := VerifyToken(r)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)

	if ok && token.Valid {
		accessUuid, ok := claims["access_uuid"].(string)
		if !ok {
			fmt.Println("extract error1")
			return nil, err
		}
		userId, ok1 := claims["user_id"].(string)
		if !ok1 {
			fmt.Println("extract error2")
			return nil, err
		}

		return &AccessDetails{
			AccessUuid: accessUuid,
			UserId:     userId,
		}, nil
	}
	fmt.Println("notOk")
	return nil, err

}

func FetchAuth(authD *AccessDetails) (string, error) {
	userid, err := client.Get(ctx, authD.AccessUuid).Result()
	if err != nil {
		fmt.Println("feeror1")
		return "", err
	}

	if authD.UserId != userid {
		fmt.Println("feeror2")
		return "", fmt.Errorf("error")
	}
	return userid, nil
}
func Authorisation(c *gin.Context) {

	//Extract the access token metadata
	metadata, err := ExtractTokenMetadata(c.Request)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"Status":  "unauthorized",
			"message": "Invalid Token",
		})
		fmt.Println("authError2")
		return

	}
	userId, err1 := FetchAuth(metadata)
	if err1 != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"Status":       "unauthorized",
			"message":      " Token Expired",
			"ErrorMessage": err1.Error(),
		})
		fmt.Println("authError3")
		return

	}
	c.Set("userId", userId)

}

func UpdateHandler(c *gin.Context) {
	var empUpdate interface{}
	userId, ok := c.Get("userId")
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{

			"message": "Error while fetching userId fromauth token",
		})
	}
	oid, _ := primitive.ObjectIDFromHex(userId.(string))
	filter := bson.D{{"_id", oid}}
	if err := c.ShouldBindJSON(&empUpdate); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   err.Error(),
			"message": "Error in binding json",
		})
		return
	}

	update := bson.M{
		"$set": empUpdate,
	}
	err := collection.FindOneAndUpdate(context.TODO(), filter, update).Err()
	if err != nil {
		c.JSON(400, gin.H{
			"status":  "Failure",
			"message": err.Error(),
		})
		return

	}

	c.JSON(200, gin.H{
		"status":  "Success",
		"message": "updated Successfully",
	})

}
func SearchHandler(c *gin.Context) {
	var results []*EmployeeDetails

	//compare the user from the request, with the one we defined:
	// findOptions := options.Find()
	term := c.Param("term")
	filters := bson.M{"active": true, "$or": []bson.M{{"skills": term}, {"address": term}, {"name": term}, {"department": term}}}
	projection := bson.D{
		{"_id", 1},
		{"department", 1},
		{"skills", 1},
		{"address", 1},
		{"name", 1},
	}
	cur, err := collection.Find(context.TODO(), filters, options.Find().SetProjection(projection))
	if err != nil {
		c.JSON(500, gin.H{
			"status":  "Failure",
			"message": "Error while fetching Data from mongoDB",
		})
		return

	}

	// Iterate through the cursor
	for cur.Next(context.TODO()) {
		var elem EmployeeDetails
		err := cur.Decode(&elem)
		if err != nil {
			log.Fatal(err)
		}

		results = append(results, &elem)
	}

	if err1 := cur.Err(); err1 != nil {
		c.JSON(http.StatusBadRequest, err1.Error())
		return
	}

	// Close the cursor once finished
	cur.Close(context.TODO())

	fmt.Printf("Found multiple documents (array of pointers): %+v\n", results)

	c.JSON(http.StatusOK, results)

}

func DeleteHandler(c *gin.Context) {

	//compare the user from the request, with the one we defined:
	userId, ok := c.Get("userId")
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Error while fetching userId fromauth token",
		})
	}
	oid, _ := primitive.ObjectIDFromHex(userId.(string))
	filter := bson.D{{"_id", oid}}

	pDelete, err := strconv.ParseBool(c.DefaultQuery("permanentlyDelete", "false"))
	if err != nil {
		c.JSON(400, gin.H{
			"status":  "Failure",
			"message": "Either true or false should be sent in permanentlyDelete Params",
		})
		return
	}
	if pDelete {

		_, err := collection.DeleteOne(context.TODO(), filter)
		if err != nil {
			c.JSON(200, gin.H{
				"status":  "Failure",
				"message": "Error while Deleting Data from mongoDB",
			})
			return

		}

		c.JSON(200, gin.H{
			"status":  "Success",
			"message": "Deleted Successfully",
		})

	} else {
		update := bson.M{
			"$set": bson.M{"active": false},
		}
		err := collection.FindOneAndUpdate(context.TODO(), filter, update).Err()
		if err != nil {
			c.JSON(500, gin.H{
				"status":  "Failure",
				"message": err.Error(),
			})
			return

		}

		c.JSON(200, gin.H{
			"status":  "Success",
			"message": "Deactivated Successfully",
		})

	}

}

func RestoreHandler(c *gin.Context) {

	userId, ok := c.Get("userId")
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": "Failure",

			"message": "Error while fetching userId fromauth token",
		})
	}
	oid, _ := primitive.ObjectIDFromHex(userId.(string))

	filter := bson.D{{"_id", oid}, {"active", false}}

	update := bson.M{
		"$set": bson.M{
			"active": true,
		},
	}
	err := collection.FindOneAndUpdate(context.TODO(), filter, update).Err()
	if err != nil {
		c.JSON(500, gin.H{
			"status":  "Failure",
			"message": err.Error(),
		})
		return

	}

	c.JSON(200, gin.H{
		"status":  "Success",
		"message": "Restored Successfully",
	})

}
func DeleteRefresh(c *gin.Context) (string, error) {
	mapToken := map[string]string{}
	if err := c.ShouldBindJSON(&mapToken); err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return "", err
	}
	refreshToken := mapToken["refresh_token"]

	//verify the token
	os.Setenv("REFRESH_SECRET", "mcmvmkmsdnfsdmfdsjf") //this should be in an env file
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("REFRESH_SECRET")), nil
	})
	//if there is an error, the token must have expired
	if err != nil {
		fmt.Println("the error: ", err)
		c.JSON(http.StatusUnauthorized, "Refresh token expired")
		return "", err
	}
	//is token valid?
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		c.JSON(http.StatusUnauthorized, "Invalid JWt token")
		return "", err
	}
	//Since token is valid, get the uuid:
	claims, ok := token.Claims.(jwt.MapClaims) //the token claims should conform to MapClaims
	if ok && token.Valid {
		refreshUuid, ok := claims["refresh_uuid"].(string) //convert the interface to string
		if !ok {
			c.JSON(http.StatusUnprocessableEntity, "Unable to Process refresh_uuid")
			return "", errors.New("Unable to Process refresh_uuid")
		}
		userId, ok1 := claims["user_id"].(string)
		if !ok1 {
			c.JSON(http.StatusUnprocessableEntity, "Unable to Process user_id")
			return "", errors.New("Unable to Process user_id")
		}
		//Delete the previous Refresh Token
		deleted, delErr := DeleteAuth(refreshUuid)
		if delErr != nil { //if any goes wrong
			c.JSON(http.StatusForbidden, "Error While Deleting Refresh Token")
			return "", delErr
		} else if deleted != 1 {
			c.JSON(http.StatusUnauthorized, "Invalid Refresh Token or might have expired")
			return "", errors.New("token might have expired or Invalid")

		}
		fmt.Printf("wrongone")
		return userId, nil
	} else {
		c.JSON(http.StatusUnauthorized, "Invalid Token")
		return "", errors.New("Invalid RefreshToken")
	}
}
func RefreshHandler(c *gin.Context) {
	userId, err := DeleteRefresh(c)
	if err != nil {
		return
	} else {
		//Create new pairs of refresh and access tokens
		ts, createErr := CreateToken(userId)
		if createErr != nil {
			c.JSON(http.StatusForbidden, createErr.Error())
			return
		}
		//save the tokens metadata to redis
		saveErr := CreateAuth(userId, ts)
		if saveErr != nil {
			c.JSON(http.StatusForbidden, saveErr.Error())
			return
		}
		tokens := map[string]string{
			"access_token":  ts.AccessToken,
			"refresh_token": ts.RefreshToken,
		}
		c.JSON(http.StatusCreated, tokens)

	}

}
func DeleteTokens(authD *AccessDetails) error {

	//delete access token
	deletedAt, err := client.Del(ctx, authD.AccessUuid).Result()
	if err != nil {
		return err
	}
	//delete refresh token
	//When the record is deleted, the return value is 1
	if deletedAt != 1 {
		return errors.New("something went wrong")
	}
	return nil
}

func DeleteAuth(givenUuid string) (int64, error) {
	deleted, err := client.Del(ctx, givenUuid).Result()
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

func LogoutHandler(c *gin.Context) {
	metadata, err := ExtractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"Status":  "unauthorized",
			"message": "Invalid Token",
		})
		return
	}
	delErr := DeleteTokens(metadata)
	if delErr != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"Status":  "unauthorized",
			"message": "Token Expired",
		})

		return
	}
	_, err = DeleteRefresh(c)
	if err != nil {
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":  "Success",
		"message": "Successfully logged out",
	})

}

func main() {

	// // Some dummy data to add to the Database
	// ash := Trainer{"Ash", 10, "Pallet Town"}
	// misty := Trainer{"Misty", 10, "Cerulean City"}
	// brock := Trainer{"Brock", 15, "Pewter City"}

	router := gin.Default()

	router.POST("/add", func(c *gin.Context) {

		var emp Employee
		var result Employee
		if err := c.ShouldBindJSON(&emp); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   err.Error(),
				"message": "Error in binding json",
			})
			return
		}

		if err := validator.Validate(emp); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   err.Error(),
				"message": "Error validation",
			})
			return
		}

		filter := bson.D{{"name", emp.Name}, {"password", emp.Password}}
		//compare the user from the request, with the one we defined:
		err := collection.FindOne(context.TODO(), filter).Decode(&result)
		if err == nil {
			c.JSON(400, gin.H{
				"status":  "Failure",
				"message": fmt.Sprintf("data is already created with %s", emp.Name),
			})
			return
		}
		emp.Active = true

		// Insert a single document
		insertResult, err := collection.InsertOne(context.TODO(), emp)
		if err != nil {
			c.JSON(500, gin.H{
				"status":  "Failure",
				"message": "Error While Inserting Data",
			})
		}
		fmt.Println("Inserted a single document: ", insertResult.InsertedID)
		c.JSON(200, gin.H{
			"status":  "Success",
			"message": "inserted successfully",
		})
	})

	router.POST("/login", func(c *gin.Context) {
		var result Employee
		filter := bson.D{{"name", c.PostForm("name")}, {"password", c.PostForm("password")}}
		//compare the user from the request, with the one we defined:
		err1 := collection.FindOne(context.TODO(), filter).Decode(&result)
		if err1 != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"status":  "Failure",
				"message": "Invalid UserName or Password",
			})
			return
		}

		token, err := CreateToken(result.EmployeeId)
		if err != nil {
			c.JSON(http.StatusUnprocessableEntity, err.Error())
			return
		}
		fmt.Println(result.EmployeeId)
		saveErr := CreateAuth(result.EmployeeId, token)
		if saveErr != nil {
			c.JSON(http.StatusUnprocessableEntity, saveErr.Error())
			return
		}
		c.JSON(http.StatusOK, token)
	})
	router.POST("/refresh", RefreshHandler)
	router.POST("/logout", LogoutHandler)

	api := router.Group("/auth")
	api.Use(Authorisation)
	{
		api.GET("/list", ListHandler)
		api.GET("/search/:term", SearchHandler)
		api.PUT("/restore", RestoreHandler)
		api.DELETE("/delete", DeleteHandler)
		api.PUT("//update", UpdateHandler)

	}

	router.Run(":8080")

}
