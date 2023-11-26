package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"gopkg.in/yaml.v2"
)

type Config struct {
	sshHostname string `yaml:"ssh_hostname"`
	sshPort     int    `yaml:"ssh_port"`
	sshUsername string `yaml:"ssh_username"`
	Database    struct {
		atpHostname   string `yaml:"atp_hostname"`
		atpPort       int    `yaml:"atp_port"`
		atpUsername   string `yaml:"atp_username"`
		atpWalletPath string `yaml:"atp_wallet_path"`
		atpWalletName string `yaml:"atp_wallet_name"`
		atpPassword   string `yaml:"atp_password"`
	} `yaml:"database"`
}

func main() {
	// Read YAML file
	content, err := os.ReadFile("tunnel.yaml")
	if err != nil {
		log.Fatalf("Failed to read YAML file: %v", err)
	}

	// Parse YAML into Config struct
	var ymlconfig Config
	err = yaml.Unmarshal(content, &ymlconfig)
	if err != nil {
		log.Fatalf("Failed to parse YAML: %v", err)
	}

	// Load the private key from your SSH agent
	authMethod, err := agentAuth()
	if err != nil {
		log.Fatalf("Failed to get SSH auth method: %v", err)
	}

	// Read the wallet file
	// walletFilePath := "/path/to/wallet_directory"
	wallet, err := os.ReadFile(filepath.Join(ymlconfig.Database.atpWalletPath, ymlconfig.Database.atpWalletName))
	if err != nil {
		log.Fatalf("Failed to read wallet file: %v", err)
	}

	// Configure the SSH client
	config := &ssh.ClientConfig{
		User: ymlconfig.sshUsername,
		Auth: []ssh.AuthMethod{authMethod},
	}

	// Connect to the SSH server
	conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", ymlconfig.sshHostname, ymlconfig.sshPort), config)
	if err != nil {
		log.Fatalf("Failed to connect to SSH server: %v", err)
	}
	defer conn.Close()

	// Start the port forwarding
	listener, err := conn.Listen("tcp", "localhost:1522")
	if err != nil {
		log.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	log.Println("Port forwarding started on localhost:1522")

	// Handle incoming connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalf("Failed to accept connection: %v", err)
		}

		go handleConnection(conn, wallet, ymlconfig)
	}
}

func handleConnection(conn net.Conn, wallet []byte, ymlconfig Config) {
	remoteAddr := fmt.Sprintf("%s:%d", ymlconfig.Database.atpHostname, ymlconfig.Database.atpPort)
	target, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		log.Fatalf("Failed to connect to target: %v", err)
	}
	defer target.Close()

	// Write the wallet data to the target connection
	if _, err := target.Write(wallet); err != nil {
		log.Fatalf("Failed to write wallet data to target: %v", err)
	}

	// Copy the data between connections bidirectionally
	go func() {
		if _, err := io.Copy(conn, target); err != nil {
			log.Fatalf("Failed to copy data from target to connection: %v", err)
		}
	}()

	go func() {
		if _, err := io.Copy(target, conn); err != nil {
			log.Fatalf("Failed to copy data from connection to target: %v", err)
		}
	}()
}

func agentAuth() (ssh.AuthMethod, error) {
	// Get the current user's home directory
	usr, err := user.Current()
	if err != nil {
		return nil, err
	}

	// Connect to the SSH agent
	socketPath := filepath.Join(usr.HomeDir, ".ssh", "agent.sock")
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Create the SSH agent client
	agentClient := agent.NewClient(conn)

	// Request identities from the agent
	signers, err := agentClient.Signers()
	if err != nil {
		return nil, err
	}

	// Create an SSH auth method using the signers
	authMethod := ssh.PublicKeys(signers...)

	return authMethod, nil
}
