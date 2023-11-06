/* Implementation file for a vulnerability database system that obtains username and password for authentication
* where the user has only 3 attempts right.
*
* Then, the program obtains the preference of the user (read, write, and exit)
* This process is repeated until the user chooses the exit
*
* In the case of write option is chosen, the user must enter the e-mail address
* which is already kept in the corporate system for 2FA (two-factor-authorization)
*
* In the case of the read option being chosen, the CVE number is obtained from the user and related data is read
*
* In the case of the exit option being chosen, the option to read new publicly released attacks offers to the user
*/

//Linking other header files
#include<iostream>
#include<fstream>
#include<regex>
#include<stdio.h>
#include<unordered_set> 
#include<limits>
#include<vector>
#include"spec.h"

//Namespace definition
using namespace std;

//Static CVE number attribute
string User :: CVE;

//Static mail attribute
string User :: mail;

////Function to set obtained username and password attribute
//Post-condition: Obtained username and password attribute will be assigned
void User :: setUsnameAndPass(string& userName, string& passWord) {

    //Assigning related attributes via this pointer
    this -> username = userName;
    this -> password = passWord;
}

//Function to check username and password at the beginning of the program to authenticate user for entering the system 
//Function compares usernames and password from seperated file record
//Post-condition: function returns true if username and password are matched the one within the records
bool User :: checkUser(const string &passWord, const string &userName) {

    //Variable to hold data of line
    string line;

    //Username and password data transfer from the file
    string fileUsername;
    string filePassword;

    //Opening the text file for reading
    ifstream inputFile;
    inputFile.open("password.txt", ios :: in);

    //In the case of file is not opened
    if(!inputFile) {

        //Informing user
        cerr << "File couldn't opened.\n";
        return false;
    }

    //Reading the file line by line
    while (getline(inputFile, line)) {

        //Splitting the line into username and password
        size_t pos = line.find(":");

        //Username and password data transfer from the file
        fileUsername = line.substr(0, pos);
        filePassword = line.substr(pos + 1, 4);

        //Compare the given username and password to the ones in the file
        if ((!userName.compare(fileUsername)) && (!(passWord.compare(filePassword)))) {

            //In the case of username and password are valid
            return true;
        }
    }

    //Closing the password file
    inputFile.close();

    //In the case of username and password were not found in the file
    return false;
}

//Function to obtain CVE number from user
//Post-condition: Obtained CVE number is assigned CVE attribute of the object (user, which is static)
void User :: obtainCVE( ){

    //Variable to hold temporary cve number
    string cve;
    
    //Variables to hold information of substring formats
    string str1, str2, str3, str4, str5;

    //Sentinel value
    bool done(false);
    
    //Informing the user
    cout << "Please, enter CVE number:";

    //Assigning CVE number
    getline(cin, cve);
    
    //Obtaining process of CVE until expected format is provided
    while(!done){

        //Determining whether obtained cve number provides format requirements after splitting CVE number to the substrings
        try {

            //In the case of cve lenght is less than 3
            if (cve.length() < 3) {

                //Throw statement
                throw InvalidInputException("Size of the string must be at least 3.\n");
            }

            //If string lenght is more than or eql 3, then split the first three characters to check format later (which must hold 'CVE')
            str1 = cve.substr(0,3);
            
            //In the case of cve lenght is less than 4
            if (cve.length() < 4) {

                //Throw statement
                throw InvalidInputException("Size of the string must be at least 4.\n");
            }

            //If string lenght is more than or eql 4, then split the fourth character to check format later (which must hold '-')
            str2 = cve.substr(3,1);

            //In the case of cve lenght is less than 8
            if (cve.length() < 8) {

                //Throw statement
                throw InvalidInputException("Size of the string must be at least 8.\n");
            }

            //If string lenght is more than or eql 8, then split the next four character to check format later (which must hold 'NNNN', N = number)
            str3 = cve.substr(4,4);

            //In the case of cve lenght is less than 9
            if (cve.length() < 9) {

                //Throw statement
                throw InvalidInputException("Size of the string must be at least 9.\n");
            }

            //If string lenght is more than or eql 9, then split the next four character to check format later (which must hold 'NNNN', N = number)
            str4 = cve.substr(8,1);

            //Splitting characters from ninth character to the end of CVE number (which must hold NNN... )
            str5 = cve.substr(9);

            //Format checking (CVE-NNNN-NNN...)
            if(str1 != "CVE") {

                //Throw statement
                throw InvalidInputException("The string must start with 'CVE' prefix.\n");
            }
            
            if(str2 != "-") {

                //Throw statement
                throw InvalidInputException("The string must include '-' character after 'CVE' prefix.\n");
            }
        
            if(str3.find_first_not_of("0123456789") != string::npos) {

                //Throw statement
                throw InvalidInputException("The string must include 4 digits after the first '-' character.\n");
            }
        
            if(str4 != "-") {

                //Throw statement
                throw InvalidInputException("The string must include '-' character after the first 4 digits.\n");  
            }
        
            if(str5.find_first_not_of("0123456789") != string::npos) {

                //Throw statement
                throw InvalidInputException("The string must include 4 or more digits after the second '-' character.\n"); 
            }    
            //Termination process of format checking
        
            //In the case of no exception is thrown, cve obtaining process will be terminated
            done = true;
            CVE = cve;
        }

        //If any exception is thrown, obtain CVE again after restoring input stream
	    catch(InvalidInputException exception) {

            //Restoring input stream after invalid input
            cin.clear();
            cin.ignore(numeric_limits <streamsize> :: max(), '\n');

            //Informing user
            cout << "Expected format of CVE number didn't provided, please try again.\n";
            cout << exception.what() << endl;

            //Obtaining CVE
            getline(cin, cve);
        }
    } 
}

//Function to search for a given pattern (CVE number) within the lines of an input file
//Post-condition: returns 1 if the pattern is found, 0 if the pattern is not found
int User :: searchCVE(ifstream& inputFile) {

    //Temporary string variable to hold line that readed from the file
    string line;

    //Loop to search file
    while (getline(inputFile, line)) {

        //In the case of related CVE number is found
        if (line.find(CVE) != string::npos) {

            //Return status
            return 1;
        }
    }
    
    //Return status
    return 0;
}

//Function to read related data
//Post-condition: In the case of a matched found with related CVE number, function outputs information details about related CVE number
void User :: read(ifstream& readFile) {

    // Determining whether obtained CVE number matched one of the CVE numbers in system, cursor passed next line
    if (searchCVE(readFile)) {

        //Creating temporary variable to hold line information of related file
        string lineData;

        //Creating a dynamic array to store the lines in memory
        vector <string> lines;

        //Read lines until the line of '=' found
        while (getline(readFile, lineData)) {

            //If line with sequence of '=' found
            if (lineData.find('=') != string :: npos) {

                //Stop reading
                break;
            }

            //If cursor doesn't reach to final line of data related CVE number, transfer content of line to vector
            lines.push_back(lineData);
        }

        //Read lines from the container and print them to the console via iterator
        for (vector <string> :: iterator it = lines.begin(); it != lines.end(); ++it) {

            //Retrieving contents via dereferencing the iterator
            cout << *it << endl;
        }
    }

    //In the case of CVE number couldn't be found in the file
    else {

        //Informing the user
        cout << "Given CVE number couldn't found in the system.\n";
    }
}

//Function to obtain mail address of user and verify whether it is verified format (user has 2 attempt right)
//Post-condition: In the case of mail address is verified, user verified mail address and now able to write on the system (in the successful situation, returns 1)
int User :: obtainMail() {
    
    //Determining expected mail format
    const regex pattern("(\\w+)(\\.|_)?(\\w*)@(\\w+)(\\.(\\w+))+");

    //Temporary variable to hold mail address
    string str;

    //Obtaining mail address from user
    cout << "Please, enter your Email-Id:" << endl;

    //Variable to determine whether inputting process succesfull (0 == not successful, repeat)
    int done(0);

    //Variable to track attempt number
    int attempt(0);

    //Assigning obtained mail address to the temporary variable
    getline(cin, str);

    //Obtaining mail address until expected mail format requirements provided
    while(done == 0) {

        try {

            //If expected format is not provided
            if(!(regex_match(str,pattern))) {

                //Throw statement
                throw InvalidInputException("Invalid mail address is inputted, please try again.\n");
            }

            //If expected format is provided
            mail = str;

            //Terminate the process
            done = 1;

            //return status
            return(1);
        }

        catch(InvalidInputException exception) {

            //Restoring input stream after invalid input
            cin.clear();
            cin.ignore(numeric_limits <streamsize> :: max(), '\n');

            //Informing user
            cout << exception.what() << endl;

            //Obtaining CVE
            getline(cin, str);

            //Tracking the number of attempt
            attempt++;

            //If user used all invalid mail address entry right, terminate the process
            if(attempt == 2) {
                break;
            }
        }
    }

    //Return status
    return(0);
}

//Function to overload outstream variable to print all attributes of an User class object
//Post-condition: Username and password will be printed
ostream& operator<<(ostream &out, const User &user) {

    //Username information will be printed
    out << "User " << user.username;

    //Mail information will be printed
    out << " with mail address " << user.mail;
    out << " is entering the system" << endl;

    //Return statement
    return out;
}

//Function to write on the system which will direct user overrided write functions after 2FA
//Post-condition: related error message will be printed
void User :: write() {

    //Informing user
    cout << "Failed writing process\n";
}

//Function to make change in the system records
//Post-condition: Obtained data will be entered to system after 2FA
void Authorized :: write() {
	
    //Outstream variable to modify records in the file
	ofstream cveFile;

    //Variable to hold temporary data which will be recorded
    string inData;

    //File opening process
    cveFile.open("record.txt", ios :: app);

    //In the case of file is not opened
    if(!cveFile) {
        
        //Informing user
        cerr << "File couldn't opened.\n";
    }

    //Informing user
    cout << "When you are finished typing, please press enter and type done.\n" << 
            "Please enter the records of only one at a time with respect to CVE number " << endl;	
	
    //Loop for obtaining data
	while (cveFile.is_open()) {

        //Obtaining data
        getline(cin, inData);
        
        //Control statement to determine end of process
		if(inData == "done" || inData == "Done" || inData == "DONE"){

            //In the case of termination of the writing process end line will be inputted
			cveFile << "\n==============================================" << endl;

            //Termination of the writing process
			break;
		}
        
        //Writing on the file
		cveFile << inData << endl;	
    }
    
    //Informing the user
	cout << "\nThis program succesfully stored in the file.";

    //Closing the file
	cveFile.close();
}

//Overrided write function to inform the user about no acces to records
//Post-condition: User will be informed about no acces to write
 void Unauthorized :: write() {

    //Informing the user
     cerr << endl << "Permission denied for Unauthorized writer!!" << endl;
}

//Function to determine whether user want to read beyond about new released attacks
//Post-condition: User will be directed related website by sharing URL of the up-to-date website
void User:: extraRead() {

    //Informing the user
    cout << "You chose to read beyond about new released attacks and methods.\n"
         << "Please visit the website via provided URL: "
         << "https://attack.mitre.org/resources/updates/ "
         << endl;
}

//Virtual destructor for User class
User :: ~User() { }

//Default constructor of Invalid Input Exception class
//Post-condition: Default message will be assigned
InvalidInputException :: InvalidInputException() {

    //Default message
    message = "Invalid CVE format.\n";
}

//Overloaded constructor of Invalid Input Exception class
//Post-condition: Error message that obtained from user will be assigned
InvalidInputException :: InvalidInputException(string str) {

    //Assignment operation to message attribute from error message inputted by user
    message = str;
}

//Function to return error message 
//Post-condition: Error message will be thrown
string InvalidInputException :: what() {

    //Return status
    return message;
}
