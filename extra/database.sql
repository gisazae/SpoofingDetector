DROP TABLE detection_log;
DROP TABLE attack_log;


CREATE TABLE attack_log(
	at_id integer primary key autoincrement,
	at_date date not null,
	at_type text,
	at_user text,
	at_result boolean
);

CREATE TABLE detection_log(
	de_id integer primary key autoincrement,
	de_date date not null,
	de_type text
);


