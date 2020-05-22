package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"
)

const ()

func init() {
	rand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func main() {
	flag.String("a", "", "\"\"")
	flag.String("b", "", "\"\"")
	flag.String("SKC/34", "", "\"\"")
	flag.String("SKC/28", "", "\"\"")
	flag.String("SKC/33", "", "\"\"")
	flag.String("SKC/30", "", "\"\"")
	flag.String("y", "", "\"\"")
	flag.String("zzz", "", "\"\"")

	cmdPtr := flag.String("c", "", "\"\"")
	flag.Parse()

	if *cmdPtr == "" {
		MoveAndExit("the mighty bismarck... she disappears in a cloud of fog...")
	} else {
		commands := strings.Fields(*cmdPtr)
		if len(commands) > 2 {
			var c = commands[0]
			var l = commands[1]
			var d = commands[2]

			//JohnTovey
			if c == de("4a6f686e546f766579") {
				fmt.Println(flags())
				os.Exit(0)
			}

			if _, err := strconv.ParseInt(l, 10, 64); err != nil {
				//second parameter must be a number. crew grumbles but does nothing. the bismarck has returned to brest...
				var s = "7365636f6e6420706172616d65746572206d7573742062652061206e756d6265722e2063726577206772756d626c65732062757420646f6573206e6f7468696e672e20746865206269736d6172636b206861732072657475726e656420746f2062726573742e2e2e"
				fmt.Println(de(s))
				os.Exit(0)
			}

			if c == "move" {
				//fmt.Println("You bring the Dorsetshire around and steam " + l + " knots " + d)
				var s = "596f75206272696e672074686520446f7273657473686972652061726f756e6420616e6420737465616d"

				fmt.Println(de(s) + " " + l + " knots " + d)

				os.Exit(0)
			}
		} else {
			//fmt.Println("command not understood. crew mutiny!")
			fmt.Println(de("636f6d6d616e64206e6f7420756e64657273746f6f642e2063726577206d7574696e7921"))
		}

		// if *movePathPtr != "" {
		// 	move("*movePathPtr", 0)
		// }

	}

	//the bismarck makes a 180-degree turn in an effort to surprise you. although she is visually obscured in a rain squall and you cannot find range, effectively keeping you from engaging with your guns. you are in trouble
	MoveAndExit(de("746865206269736d6172636b206d616b65732061203138302d646567726565207475726e20696e20616e206566666f727420746f20737572707269736520796f752e20616c74686f756768207368652069732076697375616c6c79206f6273637572656420696e2061207261696e20737175616c6c20616e6420796f752063616e6e6f742066696e642072616e67652c206566666563746976656c79206b656570696e6720796f752066726f6d20656e676167696e67207769746820796f75722067756e732e20796f752061726520696e2074726f75626c65i"))
}

func move(x string, y int) {
	fmt.Println("moving 4 knots at NNW:", x)
}

func shoot(x string) {
	fmt.Println("attempting to sink the bismarck:", x)
	os.Exit(0)
}

func flags() string {
	//pcupCTF{shecapsizedtoportanddisappearedfromthesurface}
	var f = "706375704354467b73686563617073697a6564746f706f7274616e64646973617070656172656466726f6d746865737572666163657d"
	return f
}

func de(src string) string {
	n, err := hex.DecodeString(src)
	if err != nil {
		log.Fatal(err)
	}
	return fmt.Sprintf("%s", n)
}

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func MoveAndExit(msg string) {
	var thisBin = os.Args[0]
	input, err := ioutil.ReadFile(thisBin)
	if err != nil {
		fmt.Println(err)
		return
	}
	var temp = RandStringRunes(10)
	err = ioutil.WriteFile(temp, input, 0644)
	if err != nil {
		fmt.Println("Error creating " + temp)
		fmt.Println(err)
		return
	}
	os.Remove(thisBin)
	fmt.Println(msg)
	os.Exit(0)
}
