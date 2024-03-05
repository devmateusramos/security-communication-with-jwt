package credential

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"time"
)

// This should be removed and use the public e private key from env variable
func generateKeys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return publicKey, privateKey, nil

}

func GenerateCredential(privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey) (string, error) {

	var issuerRole, subjectRole string
	issuerRole = "Operators"
	subjectRole = "Accounts"

	// Criando um token JWT
	token := jwt.New(jwt.SigningMethodEdDSA)
	claims := token.Claims.(jwt.MapClaims)
	claims["iss"] = publicKey
	claims["sub"] = publicKey
	claims["roles"] = []string{issuerRole, subjectRole}
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix() // Expira em 24 horas

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func ValidateJWT(tokenString string, publicKey ed25519.PublicKey) error {
	// Parse do token JWT
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verificando o método de assinatura
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("invalid signing method")
		}
		return publicKey, nil
	})

	if err != nil {
		return err
	}

	// Validando as reivindicações do token
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return fmt.Errorf("invalid token")
	}

	expirationTime := time.Unix(int64(claims["exp"].(float64)), 0)
	if time.Now().After(expirationTime) {
		return fmt.Errorf("expired token")
	}

	return nil
}
