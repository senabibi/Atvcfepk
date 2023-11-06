/* Specification file for a vulnerability database system that obtains username and password for authentication
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

//Preprocessor identifier to embed multiple inclusion error for base class
#ifndef H_PROJECT
#define H_PROJECT

//Linking other header files
#include<iostream>
#include<string>


//Namespace definition
using namespace std;

//Definition of base class
class User {

    //Private attributes of base class
    private:

        //Username attribute to authenticate user / employee
        string username;

        //Password attribute to authenticate user / employee
        string password;

        //CVE number attribute to find related information
        static string CVE;

        //Code sent to user for authentication process
        static string mail;

    //Public attributes of base class
    public:             
        
        //Constructor to ensure that no instances can be created externally for singleton pattern
        User() : username (), password() { }

        //Accessor function to get username attribute
        const string getUserName( ) {                              

            //Return statement
            return username;
        }

        //Accessor function to get password attribute
        const string getPassword( ) {                            

            //Return statement
            return password;
        }

        //Function to set obtained username and password attribute
        void setUsnameAndPass(string& username, string& password);

        //Function to obtain CVE number from user
        void obtainCVE( );                                 

        //Function to search CVE number
        int searchCVE(ifstream& inputFile);                       

        //Function to read related data
        void read(ifstream &read);                               

        //Function to write (in the append mode) related data obtained from user which'll be overrided     
        virtual void write( );

        //Function to obtain mail address and check validity
        int obtainMail();

        //Function to check username and password at the beginning of the program to authenticate user for entering the system 
        bool checkUser(const string &password, const string &username);              

        //Function to determine whether user want to read beyond about new released attacks
        void extraRead( );                                                       

        //Function to overload outstream variable to print all attributes of an User class object
        friend ostream& operator<< (ostream&, const User&);    

        //Protected virtual destructor to ensure that inherited classess can call destructor while User's one should remain until termination
        virtual ~User();                                                      
};

//Definition of Authorized User class (After 2FA)
class Authorized : public User {

    //Public attributes 
    public:

        //Overrided write function to change database
        virtual void write( ) ;                           
};

//Definition of Unauthorized User class (After 2FA)
class Unauthorized : public User {

    //Public attributes 
    public:

        //Overrided write function to inform the user about no acces to records
        virtual void write( ) ;                                        
};

// User defined exception class template with a template parameter to hold the type of the invalid input
class InvalidInputException {

    //Private attributes
    private:

        //Output message
        string message;
    
    //Public attributes
    public:

        //Default constructor
        InvalidInputException();

        //Overloaded constructor
        InvalidInputException(string str);

        //Function to return output message
        string what();

        //Destructor
        ~InvalidInputException() throw() {}
};

#endif