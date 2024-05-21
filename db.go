package main
import (
	"fmt"
	"database/sql"
	_ "github.com/lib/pq"
)

var DB *sql.DB

func OpenDatabase() error {
	var err error
	DB, err = sql.Open("postgres","postgres://default:8FjOdb1EiNJq@ep-orange-pond-a4nxyy7c.us-east-1.aws.neon.tech:5432/verceldb?sslmode=require")
	if err != nil {
		return err
	}

	fmt.Println("DB is connected successfully")
	return nil


}

func CloseDatabase() error {
	return DB.Close()
}