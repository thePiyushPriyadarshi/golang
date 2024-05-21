package main
import (
	"log"
	"os"
	"net/http"
	"github.com/gin-gonic/gin" 
	"golang.org/x/crypto/bcrypt"
	"github.com/gin-contrib/cors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gofiber/fiber/v2"
	"time"
)

type user struct {
	ID string `json:"id"`
	Name string `json:"name"`
	Email string `json:"email"`
	Password string `json:"password"`
}

var secretKey = []byte("lenscorpjwtsecret")

func createToken(email string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
	jwt.MapClaims{
		"emai" : email,
		"exp" : time.Now().Add(time.Hour * 24).Unix(),
	})
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		panic(err)
		return "", err
	}
	return tokenString, nil
}

func login(c *gin.Context) {
    
	var input struct {
		Email string `json:"email" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	err := c.ShouldBindJSON(&input)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var foundUser user
	query := `SELECT id, name, email, password FROM users WHERE email=$1`
	err = DB.QueryRow(query, input.Email).Scan(&foundUser.ID, &foundUser.Name, &foundUser.Email, &foundUser.Password)
	if err != nil { 
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid email"})
			return
	    }
	
	err = bcrypt.CompareHashAndPassword([]byte(foundUser.Password), []byte(input.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Incorrect Password"})
		return
	}

    var token,error = createToken(foundUser.Email)
	if error != nil {
		panic(error)
	}
	c.JSON(http.StatusOK, gin.H{"status": true, "message": "login successful", "token" : token})
}
func register(c *gin.Context) {
	var newUser user
	err := c.ShouldBindJSON(&newUser)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
	insertStmt := `insert into "users"("name","email","password") values($1,$2,$3)`
	_, e := DB.Exec(insertStmt, newUser.Name, newUser.Email,hashedPassword)
	if e != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": e.Error(),"status" : false})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": true, "message" : "Registration successfully"})
}

func main(){
	err := OpenDatabase()
	if err != nil {
		log.Printf("error connection to postgressql database %v",err);
	}
	defer CloseDatabase();

	router := gin.Default()
	router.Use(cors.Default())

	router.POST("/login",login)
	router.POST("/register", register)

	// http.HandleFunc("/createUser",createUser)
	app := fiber.New()
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Server is running and up")
	})
	app.Get("/evn", func(c *fiber.Ctx) error {
		return c.SendString("Hello, ENV"+os.Getenv("TEST_ENV"))
	})
  port := os.Getenv("PORT")

  if port == "" {
	port = "3000"
  }
	router.Run("0.0.0.0:"+port)
}