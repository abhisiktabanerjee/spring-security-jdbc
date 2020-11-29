INSERT into users (username, password ,enabled)
values('user', 
	'pass',
	true);

INSERT into users (username, password ,enabled)
values('admin', 
	'pass', 
	true);

INSERT into authorities (username, authority)
values('user', 'ROLE_USER');

INSERT into authorities (username, authority)
values('user', 'ROLE_ADMIN');
