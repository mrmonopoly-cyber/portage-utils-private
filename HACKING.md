# New applets

Adding applets is easy using the q framework.

Note: Please try to keep applet names under 8 chars.

- cp template.c qmyapplet.c (all applets use the prefix of the letter 'q') 
- applets.h: add your prototype (see DECLARE_APPLET macro)
- applets.h: add a new line to applets[] following the existing syntax
- run `make depend` to auto regenerate dependent files

When and where you can please try to use an existing applet and extend 
on its functionality by adding more options vs adding a bunch of new 
little applets.

- Keep behavior consistent
	- matching:
		- default is sloppy match
		- -e exact match
		- -r regex match
