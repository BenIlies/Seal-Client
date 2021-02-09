# Seal-Client

This C++ program provides an example of interaction between a client and a server using the SEAL library.
The user inputs his values until the field he chose is empty.
Data are encrypted sent to the server which do the sum of all the encrypted values.
After having computed the sum, the result is sent back to the client that can decrypt it safely.
You can find the program related to the server on the following link : https://github.com/BenIlies/Seal-Server
The version of SEAL used here is the version 3.5.

# Installation of Microsoft SEAL

You can download SEAL on https://www.microsoft.com/en-us/research/project/microsoft-seal.
I advice you to download the same version as me if you want to follow the same installation procedure.

After having downloaded SEAL from github (gitclone works better than downloading the git).
You have to open the file SEAL.sln with Microsoft Visual Studio 2017 or with a newer version.

Build SEAL with Release x64 mode.

# Adding SEAL with your own project

Create a new project in visual studio.
Open the properties of the project.
Select All Configuration.
In the C/C++ folder, General, Additional include directories add the path where the src folder was generated after having build SEAL.
In the Linker, General, Additional Library Directories add the path where the lib was generated followed by "$(Platform)\$(Configuration)".
In the Linker, Input, Additional Dependencies add "seal.lib;"
Finally in General, General Properties, C++ Language Standard replace the current version by ISO C++ 17.

Every steps are explicitly detailed on the video below.
https://www.youtube.com/watch?v=oZQ_c89HFU0

# Scenario in detail

####
* The server creates a socket locally (ip address 127.0.0.1) on port 54000.

* The client connects himself to that server.

* The server builds the CKKS context in the example the degree of the polynomial modulus is 8192 and the coefficient modulus is the vector { 50, 20, 50 }.

* The server saves the context (serializing it) and send it to the client.

* After having received the context, the client chooses the secret and public key.

* While the server deserializes the public key, the client inputs the values on which he wants to compute the sum on client sient.

* When the user enters an empty field, the client starts encrypting data with the public key.

* When all the data is encrypted, the client sends it to the server that will compute the sum for him.

* Still with the public key the server compute the encrypted sum and sends it back to the client.

* The only secret key holder computes the decryption of the result he just received and displays it, if the value corresponds to what was expected, correctness is thus verified.

* We finally close the sockets and the connections between the two.