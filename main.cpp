 /* Driver function for a vulnerability database system that obtains username and password for authentication
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
 * 
 */

//Linking other header files
#include<iostream>
#include<fstream>
#include<string>
#include "spec.h"

//Namespace definition
using namespace std;

int main() {
    
    //Variables to hold username and password information which will be compared within the system 
    string password, username;

    //Variable to track username and password entry attempts (at most 3)
    size_t entryAttempt(0);

    //Variable to hold preference of the user(read/write/exit)
    string preference;

    //Outstream variable to modify records in the file
	ifstream inFile;

    //Variable to track the repetition of 2FA process (if != 0 , user verified)
    int twoFactorTrack(0);

    //Variable to hold typed code which is entered by user
    string typedCode;

    //Variable to determine whether obtaining preference process is done (0 is not done)
    int prefDone(0);

    //Variable to hold the preference about extra read
    string prefExtra;

    //Variable to hold value whether mail obtaining process is succesfull or not (0 == not successful)
    int mailOb(0);

    //Creating User class object (singleton)
    User employee;
    
    do {

        //Informing the user
        cout << "Please, enter username: ";

        //Obtaining username 
        getline(cin, username);
	
	//Informing the user
	cout << "\nPlease, enter password: ";
	   
        //Obtaining password
        getline(cin, password);
        

        //Determining whether user has the permission to access the system (there are 3 attempt right )
        if(employee.checkUser(password, username)) {

            //In the event of succesfull login, loop will terminate
            entryAttempt = 4;
        }
        
        else {

            //In the event of failed log in process
            entryAttempt++;

            //In the case of user has used all rights for invalid input entry
            if(entryAttempt == 3) {

                //Return status
                return (0);
            }
        }

    } while(entryAttempt < 3);

    //Assigning obtained username and password 
    employee.setUsnameAndPass(username, password);

    //Obtaining the preference of user (read/write/exit)
    do {

        //To reset preference format tracker variable to control again
        prefDone = 0;

        //Obtaining preference of user
        cout << endl << "Please enter the preference (read/write/exit): ";
        getline(cin, preference);

        //Loop to determine whether preference format is valid
        while(prefDone == 0) {

            //Controlling the format
            try {

                //In the case of preference doesn't have lowercase expected format
                if(!(preference.find("read") != string :: npos ||  preference.find("write") != string :: npos  || preference.find("exit") != string :: npos)) {

                    //Throw statement
                    throw InvalidInputException("Please choose one of the option (read/write/exit) which must be in the lowercase format.\n");
                }

                //In the case of format of preference provides requirements
                prefDone++;
            }
            catch (InvalidInputException& error) {

                //In the case of expected format is not provided, preference will be obtained again
                cout << endl << error.what();

                //Obtaining preference again
                getline(cin, preference);
            }
        }

        //In the case of read option is chosen
        if(preference.find("read") != string :: npos) {

            //In the case of preference is read, CVE number will be requested from user
            employee.obtainCVE();

            //File opening process
            inFile.open("record.txt", ios :: in);

            //Determining whether file is opened
            if(!inFile) {

                //Terminate the reading process
                break;
            }

            //Function call to read related data
            employee.read(inFile);

            //Closing the file
            inFile.close();
        }
        
        //In the case of write option is chosen
        else if (preference.find("write") != string :: npos) {
            
            if(twoFactorTrack == 0) {

                //Obtaining mail address which has to be identical with the one within the records of authorized user's mail file
                mailOb = employee.obtainMail(); //In succesfull case, mailOb is 1 otherwise 0
            
            }
            
            //In the case of user has acces to write on the system
            if(mailOb) {

                //Creating Authorized User Class object (which will be a reference to the original employee object)
                Authorized authEmployee;

                //Informing about the process
                cout << authEmployee;

                //Process of writing on the system
                authEmployee.write();

                //Increment to track variable which refers that user has access to write on system (which'll embed contigous 2FA process)
                twoFactorTrack++;
            }

            //In the case of user has no acces to write in the system
            else {
                
                //Creating UnAuthorized User Class object (which will be a reference to the original employee object)
                Unauthorized unauthEmployee;

                //Informing user
                unauthEmployee.write();

                //Decrement to track variable which refers that user has no access to write on system (which'll embed contigous 2FA process)
                twoFactorTrack = -1;
            }
        }

        //In the case of exit option is chosen
        else if(preference.find("exit") != string :: npos) {

            //Inform the user and directing to them related webpage for reading beyond about current attacks and records
            cout << endl << "Would you like to be informed about new released attacks?";
            getline(cin, prefExtra);

            if(prefExtra == "yes" || prefExtra == "Yes" || prefExtra == "YEs" || prefExtra == "YES") {

                //Directing user to related website
                employee.extraRead();
            }
        }

    } while(preference != "exit");

    //Informing the user
    cout << endl << "You chose to exit, program is terminated.";

    //Return statement
    return (0);
}

