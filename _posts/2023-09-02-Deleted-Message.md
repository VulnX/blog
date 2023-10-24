---
title: Deleted Message
date: 2023-09-02 23:41:00 + 0530
categories: [writeup, forensics]
tags: [urmia]     # TAG names should always be lowercase
---

## The Challenge

> Cyber Police have seized a computer containing illegal content, but the data stored is secured with a password. A member of the criminal organization owning the computer was arrested. Police suspect that the password was sent to the criminal via SMS, but the message was deleted right before the arrest. You’re given a dump of the data partition of the phone (running Android 6.0). Your job as the forensic specialist is to recover the deleted password.
> 
> Attachment : data.tar.gz

## The Solution

I downloaded the `data.tar.gz` file and extracted it.

Then I went into `data/com.android.messaging/` because that's the place where the deleted SMS might be stored *( "Police suspect that the password was sent to the criminal via SMS" )*. It had the following directories:
```console
$ ls                            
app_webview  cache  code_cache  databases  shared_prefs
```

I thought since message is deleted it might still be in `cache` but sadly it was empty. So naturally I explored the `databases` directory. It had the following files:
```console
$ files *
bugle_db:         SQLite 3.x database, user version 1, last written using SQLite version 3008010, file counter 16, database pages 20, cookie 0x12, schema 4, largest root page 18, UTF-8, version-valid-for 16
bugle_db-journal: data
```

Then I opened the SQL database and viewed all the tables manually:
```console
$ sqlite3 bugle_db
SQLite version 3.40.1 2022-12-28 14:03:47
Enter ".help" for usage hints.
sqlite> .tables
android_metadata               draft_parts_view             
conversation_image_parts_view  messages                     
conversation_list_view         participants                 
conversation_participants      parts                        
conversations
```

Most of them were empty, but the one in which we are interested is `parts`:
```console
sqlite> .mode column
sqlite> .header on
sqlite> SELECT * FROM parts;
_id  message_id  text                 uri  content_type  width  height  timestamp      conversation_id
---  ----------  -------------------  ---  ------------  -----  ------  -------------  ---------------
1    1           uctf{l057_1n_urm14}       text/plain    -1     -1      1691777451164  1
```

and that's how I got the flag

## FLAG

`uctf{l057_1n_urm14}`

