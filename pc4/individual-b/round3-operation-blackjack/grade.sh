#!/bin/bash

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

USER=$(logname)
init_path_1=/home/$USER/Desktop/challenge/initialize/part_1
init_path_2=/home/$USER/Desktop/challenge/initialize/part_2

ANSWER1="home/.casino"
ANSWER2=$(cat $init_path_2/flag.txt)
ANSWER3=$(cat $init_path_2/flag2.txt)


# Define the questions and their answers
question1="What is the location of the files running secret casino? Please provide the full path to the directory hosting the casino."
answer1="$ANSWER1"

question2="What is the token found in the Casino Manager's home folder?"
answer2="$ANSWER2"

question3="After decrypting the communications, enter the password to the financial logs that the aliens provided."
answer3="$ANSWER3"


# Initialize the count of correct answers to 0 and an array to keep track of which questions were answered correctly
correct_answers=0
answered_questions=()

# Loop through the questions until the user answers all three correctly
while [ $correct_answers -lt 3 ]; do
    echo "Choose a question to answer:"
    if ! [[ "${answered_questions[@]}" =~ "1" ]]; then
        echo "1. $question1"
    fi
    if ! [[ "${answered_questions[@]}" =~ "2" ]]; then
        echo "2. $question2"
    fi
    if ! [[ "${answered_questions[@]}" =~ "3" ]]; then
        echo "3. $question3"
    fi
    read -p "Enter your choice (1-3): " choice

    case $choice in
        1)
            if [[ "${answered_questions[@]}" =~ "1" ]]; then
                echo "You have already answered this question correctly."
            else
                read -p "$question1 " user_answer
                if [ "$user_answer" = "$answer1" ]; then
                    echo "Correct! Let's go back to the questions."
                    ((correct_answers++))
                    answered_questions+=("1")
                else
                    echo "Sorry, your answer is incorrect. Exiting..."
                    exit 1
                fi
            fi
            ;;
        2)
            if [[ "${answered_questions[@]}" =~ "2" ]]; then
                echo "You have already answered this question correctly."
            else
                read -p "$question2 " user_answer
                if [ "$user_answer" = "$answer2" ]; then
                    echo "Correct! Let's go back to the questions."
                    ((correct_answers++))
                    answered_questions+=("2")
                else
                    echo "Sorry, your answer is incorrect. Exiting..."
                    exit 1
                fi
            fi
            ;;
        3)
            if [[ "${answered_questions[@]}" =~ "3" ]]; then
                echo "You have already answered this question correctly."
            else
                read -p "$question3 " user_answer
                if [ "$user_answer" = "$answer3" ]; then
                    echo "Correct! Let's go back to the questions."
                    ((correct_answers++))
                    answered_questions+=("3")
                else
                    echo "Sorry, your answer is incorrect. Exiting..."
                    exit 1
                fi
            fi
            ;;
        *)
            echo "Invalid choice. Please choose a number between 1 and 3."
            continue
            ;;
    esac
done

# If the user answers all three questions correctly, print a success message
echo "Congratulations! You answered all three questions correctly."


