-- DROP TYPE public."e_gender";

CREATE TYPE public."e_gender" AS ENUM (
	'MALE',
	'FEMALE',
	'OTHER');

-- DROP TYPE public."e_user_status";

CREATE TYPE public."e_user_status" AS ENUM (
	'ACTIVE',
	'INACTIVE',
	'NONE');

-- DROP TYPE public."e_user_type";

CREATE TYPE public."e_user_type" AS ENUM (
	'OWNER',
	'ADMIN',
	'USER');

-- public.tbl_user definition

-- Drop table

-- DROP TABLE public.tbl_user;

CREATE TABLE public.tbl_user (
	id bigserial NOT NULL,
	first_name varchar(255) NOT NULL,
	last_name varchar(255) NOT NULL,
	date_of_birth date NOT NULL,
	gender public."e_gender" NOT NULL,
	phone varchar(255) NULL,
	email varchar(255) NULL,
	username varchar(255) NOT NULL,
	"password" varchar(255) NOT NULL,
	status public."e_user_status" NOT NULL,
	"type" public."e_user_type" NOT NULL,
	created_at timestamp(6) DEFAULT now() NULL,
	updated_at timestamp(6) DEFAULT now() NULL,
	CONSTRAINT tbl_user_pkey PRIMARY KEY (id)
);

-- public.tbl_address definition

-- Drop table

-- DROP TABLE public.tbl_address;

CREATE TABLE public.tbl_address (
	id bigserial NOT NULL,
	apartment_number varchar(255) NULL,
	floor varchar(255) NULL,
	building varchar(255) NULL,
	street_number varchar(255) NULL,
	street varchar(255) NULL,
	city varchar(255) NULL,
	country varchar(255) NULL,
	address_type int4 NULL,
	user_id int8 NULL,
	created_at timestamp(6) DEFAULT now() NULL,
	updated_at timestamp(6) DEFAULT now() NULL,
	CONSTRAINT tbl_address_pkey PRIMARY KEY (id)
);


-- public.tbl_address foreign keys

ALTER TABLE public.tbl_address ADD CONSTRAINT fk_address_and_user FOREIGN KEY (user_id) REFERENCES public.tbl_user(id);


INSERT INTO public.tbl_user (last_name,first_name,date_of_birth,gender,phone,email,username,"password",status,"type",created_at,updated_at) VALUES
	 ('Le','Ngan','1980-06-05','FEMALE','0123456789','someone@email.com','tayjava','password','ACTIVE','USER','2024-04-18 09:58:07.169','2024-04-18 09:58:07.169'),
	 ('Nguyen The','Minh','1981-06-05','MALE','0123456789','someone@email.com','tayjava','password','ACTIVE','USER','2024-04-18 09:56:24.587','2024-04-18 09:56:24.587'),
	 ('Le Mai','Huong','1982-07-24','FEMALE','0123456789','someone@email.com','tayjava','password','ACTIVE','USER','2024-04-18 09:58:07.611','2024-04-18 09:58:07.611'),
	 ('Dinh Van','Nam','1983-06-08','MALE','0123456789','someone@email.com','tayjava','password','ACTIVE','USER','2024-04-18 09:56:25.435','2024-04-18 09:56:25.435'),
	 ('Pham Quang','Dinh','1984-02-28','MALE','0123456789','someone@email.com','tayjava','password','ACTIVE','USER','2024-04-18 09:56:25.804','2024-04-18 09:56:25.804'),
	 ('Nguyen Thi Kim','Oanh','1985-01-01','FEMALE','0123456789','someone@email.com','tayjava','password','ACTIVE','USER','2024-04-18 09:58:08.138','2024-04-18 09:58:08.138'),
	 ('Nguyen Thi','Dung','1986-02-02','MALE','0123456789','someone@email.com','tayjava','password','ACTIVE','USER','2024-04-18 09:56:26.542','2024-04-18 09:56:26.542'),
	 ('Pham Thi','Chi','1987-03-04','FEMALE','0123456789','someone@email.com','tayjava','password','ACTIVE','USER','2024-04-18 09:58:08.589','2024-04-18 09:58:08.589'),
	 ('Tran Thuy','Dung','1988-04-05','MALE','0123456789','someone@email.com','tayjava','password','ACTIVE','USER','2024-04-18 09:56:28.438','2024-04-18 09:56:28.438'),
	 ('Dang Thanh','Tung','1989-05-06','MALE','0123456789','someone@email.com','tayjava','password','ACTIVE','USER','2024-04-18 09:56:29.231','2024-04-18 09:56:29.231'),
	 ('Nguyen Khac','Trung','1990-06-07','MALE','0123456789','someone@email.com','tayjava','password','ACTIVE','USER','2024-04-18 09:56:30.136','2024-04-18 09:56:30.136'),
	 ('Truong Hai','Kien','1991-07-09','MALE','0123456789','someone@email.com','tayjava','password','ACTIVE','USER','2024-04-18 09:56:30.6','2024-04-18 09:56:30.6'),
	 ('Vu Hong','Quan','1992-08-11','MALE','0123456789','someone@email.com','tayjava','password','ACTIVE','USER','2024-04-18 09:56:30.963','2024-04-18 09:56:30.963'),
	 ('Tran Ngoc','Tu','1993-09-12','MALE','0123456789','someone@email.com','tayjava','password','ACTIVE','USER','2024-04-18 09:56:31.3','2024-04-18 09:56:31.3'),
	 ('Dang Dinh','Tuan','1992-10-13','MALE','0123456789','someone@email.com','tayjava','password','ACTIVE','USER','2024-04-15 21:54:04.258','2024-04-15 21:54:04.258'),
	 ('Nguyen Quoc','Hung','1994-10-14','MALE','0123456789','someone@email.com','tayjava','password','ACTIVE','USER','2024-04-15 21:57:15.934','2024-04-15 21:57:15.934'),
	 ('Mai Ngoc','Que','1995-11-11','MALE','0123456789','someone@email.com','tayjava','password','NONE','USER','2024-04-15 22:02:26.532','2024-04-16 21:14:05.098'),
	 ('Tran Tu','Binh','1996-12-15','MALE','0123456789','someone@email.com','tayjava','password','ACTIVE','USER','2024-04-15 22:05:00.438','2024-04-15 22:05:00.438'),
	 ('Nguyen Hai','Thanh','1997-01-16','FEMALE','0123456789','someone@email.com','tayjava','password','ACTIVE','USER','2024-04-18 09:56:25.034','2024-04-18 09:56:25.034'),
	 ('Pham Ngoc','Hoa','1998-07-10','FEMALE','0123456789','someone@email.com','tayjava','password','ACTIVE','USER','2024-04-18 09:56:26.215','2024-04-18 09:56:26.215'),
	 ('Trinh Van','Sam','1999-01-19','FEMALE','0123456789','someone@email.com','tayjava','password','ACTIVE','USER','2024-04-18 09:56:26.88','2024-04-18 09:56:26.88'),
	 ('Kieu','My','2000-02-22','FEMALE','0123456789','someone@email.com','tayjava','password','ACTIVE','USER','2024-04-18 09:56:31.622','2024-04-18 09:56:31.622'),
	 ('Nguyen Trung','Nguyen','2003-03-12','MALE','0123456789','nguyen@email.com','nguyen','password','ACTIVE','USER','2024-04-18 09:56:22.366','2024-04-18 09:56:22.366'),
	 ('Dang','Huy','2001-04-23','MALE','0123456789','dau@email.com','dau','password','INACTIVE','USER','2024-04-18 09:56:23.573','2024-04-18 09:56:23.573'),
	 ('Minh','Khang','2002-05-25','MALE','0123456789','sumo@email.com','sumo','password','NONE','USER','2024-04-18 09:56:24.091','2024-04-18 09:56:24.091'),
	 ('Tay','Tay','2004-02-15','MALE','0123456789','tay@email.com','tay','password','ACTIVE','OWNER','2024-04-18 09:56:21.536','2024-04-18 09:56:21.536'),
	 ('Thuy','Thuy','2003-05-20','FEMALE','0123456789','thuy@email.com','thuy','password','ACTIVE','ADMIN','2024-04-18 09:56:23.06','2024-04-18 09:56:23.06');


	INSERT INTO public.tbl_address (apartment_number,floor,building,street_number,street,city,country,address_type,user_id,created_at,updated_at) VALUES
	 ('1','5','B1','101','Vo Nguyen Giap street','Hanoi','Vietnam',1,1,'2024-04-15 21:54:04.274','2024-04-15 21:54:04.274'),
	 ('2','6','B2','102','Pham Van Dong','Hue','Vietnam',1,1,'2024-04-15 21:54:04.274','2024-04-15 21:54:04.274'),
	 ('3','7','B3','103','Le Duan','Da Nang','Vietnam',1,2,'2024-04-15 22:05:00.453','2024-04-15 22:05:00.453'),
	 ('4','8','B4','104','Le Duc Tho','Sai Gon','Vietnam',1,3,'2024-04-16 21:13:28.872','2024-04-16 21:13:28.872'),
	 ('5','9','B6','105','Nguyen Chi Thanh','Can Tho','Vietnam',1,4,'2024-04-18 09:56:21.552','2024-04-18 09:56:21.552'),
	 ('6','10','B7','106','Le Trong Tan','Vung Tau','Vietnam',1,5,'2024-04-18 09:56:22.368','2024-04-18 09:56:22.368'),
	 ('7','11','A1','107','Truong Trinh','Kien Giang','Vietnam',1,6,'2024-04-18 09:56:23.061','2024-04-18 09:56:23.061'),
	 ('8','12','A2','108','Tran Dai Nghia','Soc Trang','Vietnam',1,7,'2024-04-18 09:56:23.575','2024-04-18 09:56:23.575'),
	 ('9','13','A3','109','Tran Khanh Du','Quy Nho','Vietnam',1,8,'2024-04-18 09:56:24.093','2024-04-18 09:56:24.093'),
	 ('10','14','A4','110','Tran Quang Khai','Phan Thiet','Vietnam',1,9,'2024-04-18 09:56:24.589','2024-04-18 09:56:24.589'),
	 ('11','15','A5','210','Tran Nhat Duat','Tay Ninh','Vietnam',1,10,'2024-04-18 09:56:25.037','2024-04-18 09:56:25.037'),
	 ('12','16','A6','310','Tran Tu Binh','Dak Lak','Vietnam',1,11,'2024-04-18 09:56:25.438','2024-04-18 09:56:25.438'),
	 ('13','17','A7','40','Tran Quoc Toan','Bac Giang','Vietnam',1,12,'2024-04-18 09:56:25.807','2024-04-18 09:56:25.807'),
	 ('14','18','A8','50','Tran Hung Dao','Bac Ninh','Vietnam',1,13,'2024-04-18 09:56:26.218','2024-04-18 09:56:26.218'),
	 ('15','19','Z1','60','Tran Nhan Tong','Bac Ninh','Vietnam',1,13,'2024-04-18 09:56:26.218','2024-04-18 09:56:26.218'),
	 ('16','20','X2','70','Ngo Quyen','Vinh Phuc','Vietnam',1,14,'2024-04-18 09:56:26.544','2024-04-18 09:56:26.544'),
	 ('17','21','W4','80','Khuc Thua Du','Phu Yen','Vietnam',1,15,'2024-04-18 09:56:28.442','2024-04-18 09:56:28.442'),
	 ('18','22','T2','90','Trieu Quang Phuc','Binh Dinh','Vietnam',1,16,'2024-04-18 09:56:29.232','2024-04-18 09:56:29.232'),
	 ('19','23','P2','20','Hai Ba Trung','Phan Rang','Vietnam',1,17,'2024-04-18 09:56:30.138','2024-04-18 09:56:30.138'),
	 ('20','25','G1','30','Le Loi','Dien Bien','Vietnam',1,18,'2024-04-18 09:56:30.603','2024-04-18 09:56:30.603'),
	 ('21','26','U4','111','Le Lai','Quang Ninh','Vietnam',1,19,'2024-04-18 09:56:30.965','2024-04-18 09:56:30.965'),
	 ('22','27','Y1','112','Ly Thai To','Hai Phong','Vietnam',1,20,'2024-04-18 09:56:31.303','2024-04-18 09:56:31.303'),
	 ('23','28','K1','113','Ly Thanh Tong','Tuyen Quang','Vietnam',1,21,'2024-04-18 09:56:31.624','2024-04-18 09:56:31.624'),
	 ('24','29','L1','114','Au Co','Ha Giang','Vietnam',1,22,'2024-04-18 09:58:07.172','2024-04-18 09:58:07.172'),
	 ('25','30','J2','115','Lac Long Quan','Quang Nam','Vietnam',1,23,'2024-04-18 09:58:07.613','2024-04-18 09:58:07.613'),
	 ('26','31','R3','116','Ly Nam De','Quang Ngai','Vietnam',1,24,'2024-04-18 09:58:08.139','2024-04-18 09:58:08.139'),
	 ('27','32','F2','117','Giai Phong','Binh Duong ','Vietnam',1,25,'2024-04-18 09:58:08.592','2024-04-18 09:58:08.592'),
	 ('28','33','V1','118','Bui Thi Xuan','Ben Tre','Vietnam',1,26,'2024-04-18 09:56:26.882','2024-04-18 09:56:26.882');
