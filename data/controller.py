# This is a main controller, which allows remote execution
# To run command please go to http://<SERVER_NAME>:36905/data/controller.py?security=<SECURITY_TOKEN>command=<YOUR_COMMAND>&<ADDITIONAL_ARGUMENTS_HERE> in your web browser
#
# List of commands
#    run <TYPE> <GPIO PORT> - send signals to GPIO ports
#    exec <DATA> - run python code ("data" parameter must be encrypted to a base64 format)
#    shell <DATA> - run command line command ("%20" will be replaced with a spece (" "))
#
# What is security token?
# Security token is a randomly generated number, which prevents third-party remote control. You can see it in the server console