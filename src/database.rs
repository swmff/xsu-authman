use crate::model::{Group, Notification, NotificationCreate, Permission, UserFollow};
use crate::model::{Profile, ProfileMetadata, AuthError};

use reqwest::Client as HttpClient;
use xsu_dataman::query as sqlquery;
use xsu_dataman::utility;

pub type Result<T> = std::result::Result<T, AuthError>;

#[derive(Clone, Debug)]
pub struct ServerOptions {}

impl ServerOptions {
    /// Enable all options
    pub fn truthy() -> Self {
        Self {}
    }
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {}
    }
}

/// Database connector
#[derive(Clone)]
pub struct Database {
    pub base: xsu_dataman::StarterDatabase,
    pub config: ServerOptions,
    pub http: HttpClient,
}

impl Database {
    /// Create a new [`Database`]
    pub async fn new(
        database_options: xsu_dataman::DatabaseOpts,
        server_options: ServerOptions,
    ) -> Self {
        let base = xsu_dataman::StarterDatabase::new(database_options).await;

        Self {
            base: base.clone(),
            config: server_options,
            http: HttpClient::new(),
        }
    }

    /// Pull [`dorsal::DatabaseOpts`] from env
    pub fn env_options() -> xsu_dataman::DatabaseOpts {
        use std::env::var;
        xsu_dataman::DatabaseOpts {
            r#type: match var("DB_TYPE") {
                Ok(v) => Option::Some(v),
                Err(_) => Option::None,
            },
            host: match var("DB_HOST") {
                Ok(v) => Option::Some(v),
                Err(_) => Option::None,
            },
            user: var("DB_USER").unwrap_or(String::new()),
            pass: var("DB_PASS").unwrap_or(String::new()),
            name: var("DB_NAME").unwrap_or(String::new()),
        }
    }

    /// Init database
    pub async fn init(&self) {
        // create tables
        let c = &self.base.db.client;

        let _ = sqlquery(
            "CREATE TABLE IF NOT EXISTS \"xprofiles\" (
                id       TEXT,
                username TEXT,
                password TEXT,
                tokens   TEXT,
                metadata TEXT,
                joined   TEXT,
                gid      TEXT
            )",
        )
        .execute(c)
        .await;

        let _ = sqlquery(
            "CREATE TABLE IF NOT EXISTS \"xgroups\" (
                name        TEXT,
                id          TEXT,
                permissions TEXT
            )",
        )
        .execute(c)
        .await;

        let _ = sqlquery(
            "CREATE TABLE IF NOT EXISTS \"xfollows\" (
                user      TEXT,
                following TEXT
            )",
        )
        .execute(c)
        .await;

        let _ = sqlquery(
            "CREATE TABLE IF NOT EXISTS \"xnotifications\" (
                title     TEXT,
                content   TEXT,
                address   TEXT,
                timestamp TEXT,
                id        TEXT,
                recipient TEXT
            )",
        )
        .execute(c)
        .await;
    }

    // profiles

    // GET
    /// Get a [`Profile`] by their hashed ID
    ///
    /// # Arguments:
    /// * `hashed` - `String` of the profile's hashed ID
    pub async fn get_profile_by_hashed(&self, hashed: String) -> Result<Profile> {
        // fetch from database
        let query: &str = if (self.base.db.r#type == "sqlite") | (self.base.db.r#type == "mysql") {
            "SELECT * FROM \"xprofiles\" WHERE \"tokens\" LIKE ?"
        } else {
            "SELECT * FROM \"xprofiles\" WHERE \"tokens\" LIKE $1"
        };

        let c = &self.base.db.client;
        let row = match sqlquery(query)
            .bind::<&String>(&format!("%\"{hashed}\"%"))
            .fetch_one(c)
            .await
        {
            Ok(u) => self.base.textify_row(u, Vec::new()).0,
            Err(_) => return Err(AuthError::Other),
        };

        // return
        Ok(Profile {
            id: row.get("id").unwrap().to_string(),
            username: row.get("username").unwrap().to_string(),
            password: row.get("password").unwrap().to_string(),
            tokens: match serde_json::from_str(row.get("tokens").unwrap()) {
                Ok(m) => m,
                Err(_) => return Err(AuthError::ValueError),
            },
            metadata: match serde_json::from_str(row.get("metadata").unwrap()) {
                Ok(m) => m,
                Err(_) => return Err(AuthError::ValueError),
            },
            group: row.get("gid").unwrap().parse::<i32>().unwrap_or(0),
            joined: row.get("joined").unwrap().parse::<u128>().unwrap(),
        })
    }

    /// Get a user by their unhashed ID (hashes ID and then calls [`Database::get_profile_by_hashed()`])
    ///
    /// # Arguments:
    /// * `unhashed` - `String` of the user's unhashed ID
    pub async fn get_profile_by_unhashed(&self, unhashed: String) -> Result<Profile> {
        self.get_profile_by_hashed(utility::hash(unhashed.clone()))
            .await
    }

    /// Get a user by their unhashed secondary token
    ///
    /// # Arguments:
    /// * `unhashed` - `String` of the user's unhashed secondary token
    pub async fn get_profile_by_username_password(
        &self,
        username: String,
        mut password: String,
    ) -> Result<Profile> {
        password = xsu_dataman::utility::hash(password);

        // fetch from database
        let query: &str = if (self.base.db.r#type == "sqlite") | (self.base.db.r#type == "mysql") {
            "SELECT * FROM \"xprofiles\" WHERE \"username\" = ? AND \"password\" = ?"
        } else {
            "SELECT * FROM \"xprofiles\" WHERE \"username\" = $1 AND \"password\" = $2"
        };

        let c = &self.base.db.client;
        let row = match sqlquery(query)
            .bind::<&String>(&username)
            .bind::<&String>(&password)
            .fetch_one(c)
            .await
        {
            Ok(r) => self.base.textify_row(r, Vec::new()).0,
            Err(_) => return Err(AuthError::Other),
        };

        // return
        Ok(Profile {
            id: row.get("id").unwrap().to_string(),
            username: row.get("username").unwrap().to_string(),
            password: row.get("password").unwrap().to_string(),
            tokens: match serde_json::from_str(row.get("tokens").unwrap()) {
                Ok(m) => m,
                Err(_) => return Err(AuthError::ValueError),
            },
            metadata: match serde_json::from_str(row.get("metadata").unwrap()) {
                Ok(m) => m,
                Err(_) => return Err(AuthError::ValueError),
            },
            group: row.get("gid").unwrap().parse::<i32>().unwrap_or(0),
            joined: row.get("joined").unwrap().parse::<u128>().unwrap(),
        })
    }

    /// Get a user by their username
    ///
    /// # Arguments:
    /// * `username` - `String` of the user's username
    pub async fn get_profile_by_username(&self, mut username: String) -> Result<Profile> {
        username = username.to_lowercase();

        // check in cache
        let cached = self
            .base
            .cachedb
            .get(format!("xsulib.authman.profile:{}", username))
            .await;

        if cached.is_some() {
            return Ok(serde_json::from_str::<Profile>(cached.unwrap().as_str()).unwrap());
        }

        // ...
        let query: &str = if (self.base.db.r#type == "sqlite") | (self.base.db.r#type == "mysql") {
            "SELECT * FROM \"xprofiles\" WHERE \"username\" = ?"
        } else {
            "SELECT * FROM \"xprofiles\" WHERE \"username\" = $1"
        };

        let c = &self.base.db.client;
        let row = match sqlquery(query)
            .bind::<&String>(&username)
            .fetch_one(c)
            .await
        {
            Ok(r) => self.base.textify_row(r, Vec::new()).0,
            Err(_) => return Err(AuthError::NotFound),
        };

        // store in cache
        let user = Profile {
            id: row.get("id").unwrap().to_string(),
            username: row.get("username").unwrap().to_string(),
            password: row.get("password").unwrap().to_string(),
            tokens: match serde_json::from_str(row.get("tokens").unwrap()) {
                Ok(m) => m,
                Err(_) => return Err(AuthError::ValueError),
            },
            metadata: match serde_json::from_str(row.get("metadata").unwrap()) {
                Ok(m) => m,
                Err(_) => return Err(AuthError::ValueError),
            },
            group: row.get("gid").unwrap().parse::<i32>().unwrap_or(0),
            joined: row.get("joined").unwrap().parse::<u128>().unwrap(),
        };

        self.base
            .cachedb
            .set(
                format!("xsulib.authman.profile:{}", username),
                serde_json::to_string::<Profile>(&user).unwrap(),
            )
            .await;

        // return
        Ok(user)
    }

    // SET
    /// Create a new user given their username. Returns their unhashed token
    ///
    /// # Arguments:
    /// * `username` - `String` of the user's `username`
    pub async fn create_profile(&self, username: String, password: String) -> Result<String> {
        // make sure user doesn't already exists
        if let Ok(_) = &self.get_profile_by_username(username.clone()).await {
            return Err(AuthError::MustBeUnique);
        };

        // check username
        let banned_usernames = &["admin", "account", "anonymous", "login", "sign_up"];

        let regex = regex::RegexBuilder::new(r"[^\w_\-\.!]+$")
            .multi_line(true)
            .build()
            .unwrap();

        if regex.captures(&username).is_some() {
            return Err(AuthError::ValueError);
        }

        if (username.len() < 2) | (username.len() > 500) {
            return Err(AuthError::ValueError);
        }

        if banned_usernames.contains(&username.as_str()) {
            return Err(AuthError::ValueError);
        }

        // ...
        let query: &str = if (self.base.db.r#type == "sqlite") | (self.base.db.r#type == "mysql") {
            "INSERT INTO \"xprofiles\" VALUES (?, ?, ?, ?, ?, ?, ?)"
        } else {
            "INSERT INTO \"xprofiles\" VALUES ($1, $2, $3, $4, $5, $6, $7)"
        };

        let user_token_unhashed: String = xsu_dataman::utility::uuid();
        let user_token_hashed: String = xsu_dataman::utility::hash(user_token_unhashed.clone());
        let timestamp = utility::unix_epoch_timestamp().to_string();

        let c = &self.base.db.client;
        match sqlquery(query)
            .bind::<&String>(&xsu_dataman::utility::uuid())
            .bind::<&String>(&username.to_lowercase())
            .bind::<&String>(&xsu_dataman::utility::hash(password))
            .bind::<&String>(
                &serde_json::to_string::<Vec<String>>(&vec![user_token_hashed]).unwrap(),
            )
            .bind::<&String>(
                &serde_json::to_string::<ProfileMetadata>(&ProfileMetadata::default()).unwrap(),
            )
            .bind::<&String>(&timestamp)
            .bind::<&i32>(&0)
            .execute(c)
            .await
        {
            Ok(_) => Ok(user_token_unhashed),
            Err(_) => Err(AuthError::Other),
        }
    }

    /// Update a [`Profile`]'s metadata by its `username`
    pub async fn edit_profile_metadata_by_name(
        &self,
        name: String,
        metadata: ProfileMetadata,
    ) -> Result<()> {
        // make sure user exists
        if let Err(e) = self.get_profile_by_username(name.clone()).await {
            return Err(e);
        };

        // update user
        let query: &str = if (self.base.db.r#type == "sqlite") | (self.base.db.r#type == "mysql") {
            "UPDATE \"xprofiles\" SET \"metadata\" = ? WHERE \"username\" = ?"
        } else {
            "UPDATE \"xprofiles\" SET (\"metadata\") = ($1) WHERE \"username\" = $2"
        };

        let c = &self.base.db.client;
        let meta = &serde_json::to_string(&metadata).unwrap();
        match sqlquery(query)
            .bind::<&String>(meta)
            .bind::<&String>(&name)
            .execute(c)
            .await
        {
            Ok(_) => {
                self.base
                    .cachedb
                    .remove(format!("xsulib.authman.profile:{}", name))
                    .await;
                Ok(())
            }
            Err(_) => Err(AuthError::Other),
        }
    }

    /// Update a [`Profile`]'s tokens by its `username`
    pub async fn edit_profile_tokens_by_name(
        &self,
        name: String,
        tokens: Vec<String>,
    ) -> Result<()> {
        // make sure user exists
        if let Err(e) = self.get_profile_by_username(name.clone()).await {
            return Err(e);
        };

        // update user
        let query: &str = if (self.base.db.r#type == "sqlite") | (self.base.db.r#type == "mysql") {
            "UPDATE \"xprofiles\" SET \"tokens\" = ? WHERE \"username\" = ?"
        } else {
            "UPDATE \"xprofiles\" SET (\"tokens\") = ($1) WHERE \"username\" = $2"
        };

        let c = &self.base.db.client;
        let tokens = &serde_json::to_string(&tokens).unwrap();
        match sqlquery(query)
            .bind::<&String>(tokens)
            .bind::<&String>(&name)
            .execute(c)
            .await
        {
            Ok(_) => {
                self.base
                    .cachedb
                    .remove(format!("xsulib.authman.profile:{}", name))
                    .await;
                Ok(())
            }
            Err(_) => Err(AuthError::Other),
        }
    }

    /// Update a [`Profile`]'s `gid` by its `username`
    pub async fn edit_profile_group_by_name(&self, name: String, group: i32) -> Result<()> {
        // make sure user exists
        if let Err(e) = self.get_profile_by_username(name.clone()).await {
            return Err(e);
        };

        // update user
        let query: &str = if (self.base.db.r#type == "sqlite") | (self.base.db.r#type == "mysql") {
            "UPDATE \"xprofiles\" SET \"gid\" = ? WHERE \"username\" = ?"
        } else {
            "UPDATE \"xprofiles\" SET (\"gid\") = ($1) WHERE \"username\" = $2"
        };

        let c = &self.base.db.client;
        match sqlquery(query)
            .bind::<&i32>(&group)
            .bind::<&String>(&name)
            .execute(c)
            .await
        {
            Ok(_) => {
                self.base
                    .cachedb
                    .remove(format!("xsulib.authman.profile:{}", name))
                    .await;
                Ok(())
            }
            Err(_) => Err(AuthError::Other),
        }
    }

    /// Update a [`Profile`]'s `password` by its name and password
    pub async fn edit_profile_password_by_name(
        &self,
        name: String,
        password: String,
        new_password: String,
    ) -> Result<()> {
        // make sure user exists
        if let Err(e) = self
            .get_profile_by_username_password(name.clone(), password.clone())
            .await
        {
            return Err(e);
        };

        // update user
        let query: &str = if (self.base.db.r#type == "sqlite") | (self.base.db.r#type == "mysql") {
            "UPDATE \"xprofiles\" SET \"password\" = ? WHERE \"username\" = ?"
        } else {
            "UPDATE \"xprofiles\" SET (\"password\") = ($1) WHERE \"username\" = $2"
        };

        let c = &self.base.db.client;
        match sqlquery(query)
            .bind::<&String>(&xsu_util::hash::hash(new_password))
            .bind::<&String>(&name)
            .execute(c)
            .await
        {
            Ok(_) => {
                self.base
                    .cachedb
                    .remove(format!("xsulib.authman.profile:{}", name))
                    .await;
                Ok(())
            }
            Err(_) => Err(AuthError::Other),
        }
    }

    /// Delete a profile
    ///
    /// **VALIDATION SHOULD BE DONE *BEFORE* THIS!!**
    async fn delete_profile(&self, name: String) -> Result<()> {
        // delete user
        let query: &str = if (self.base.db.r#type == "sqlite") | (self.base.db.r#type == "mysql") {
            "DELETE FROM \"xprofiles\" WHERE \"username\" = ?"
        } else {
            "DELETE FROM \"xprofiles\" WHERE \"username\" = $1"
        };

        let c = &self.base.db.client;
        match sqlquery(query).bind::<&String>(&name).execute(c).await {
            Ok(_) => {
                let query: &str =
                    if (self.base.db.r#type == "sqlite") | (self.base.db.r#type == "mysql") {
                        "DELETE FROM \"xnotifications\" WHERE \"recipient\" = ?"
                    } else {
                        "DELETE FROM \"xnotifications\" WHERE \"recipient\" = $1"
                    };

                if let Err(_) = sqlquery(query).bind::<&String>(&name).execute(c).await {
                    return Err(AuthError::Other);
                };

                let query: &str =
                    if (self.base.db.r#type == "sqlite") | (self.base.db.r#type == "mysql") {
                        "DELETE FROM \"xfollows\" WHERE \"user\" = ? OR \"following\" = ?"
                    } else {
                        "DELETE FROM \"xfollows\" WHERE \"user\" = $1 OR \"following\" = $2"
                    };

                if let Err(_) = sqlquery(query)
                    .bind::<&String>(&name)
                    .bind::<&String>(&name)
                    .execute(c)
                    .await
                {
                    return Err(AuthError::Other);
                };

                // sparkler stuff
                // questions to user
                let query: &str =
                    if (self.base.db.r#type == "sqlite") | (self.base.db.r#type == "mysql") {
                        "DELETE FROM \"xquestions\" WHERE \"recipient\" = ?"
                    } else {
                        "DELETE FROM \"xquestions\" WHERE \"recipient\" = $1"
                    };

                if let Err(_) = sqlquery(query).bind::<&String>(&name).execute(c).await {
                    return Err(AuthError::Other);
                };

                // questions by user
                let query: &str =
                    if (self.base.db.r#type == "sqlite") | (self.base.db.r#type == "mysql") {
                        "DELETE FROM \"xquestions\" WHERE \"author\" = ?"
                    } else {
                        "DELETE FROM \"xquestions\" WHERE \"author\" = $1"
                    };

                if let Err(_) = sqlquery(query).bind::<&String>(&name).execute(c).await {
                    return Err(AuthError::Other);
                };

                // responses by user
                let query: &str =
                    if (self.base.db.r#type == "sqlite") | (self.base.db.r#type == "mysql") {
                        "DELETE FROM \"xresponses\" WHERE \"author\" = ?"
                    } else {
                        "DELETE FROM \"xresponses\" WHERE \"author\" = $1"
                    };

                if let Err(_) = sqlquery(query).bind::<&String>(&name).execute(c).await {
                    return Err(AuthError::Other);
                };

                // responses to questions by user
                let query: &str =
                    if (self.base.db.r#type == "sqlite") | (self.base.db.r#type == "mysql") {
                        "DELETE FROM \"xresponses\" WHERE \"question\" LIKE ?"
                    } else {
                        "DELETE FROM \"xresponses\" WHERE \"question\" LIKE $1"
                    };

                if let Err(_) = sqlquery(query)
                    .bind::<&String>(&format!("%\"author\":\"{name}\"%"))
                    .execute(c)
                    .await
                {
                    return Err(AuthError::Other);
                };

                self.base
                    .cachedb
                    .remove(format!("xsulib.sparkler.response_count:{}", name))
                    .await;

                self.base
                    .cachedb
                    .remove(format!("xsulib.sparkler.global_question_count:{}", name))
                    .await;

                // ...
                self.base
                    .cachedb
                    .remove(format!("xsulib.authman.profile:{}", name))
                    .await;

                self.base
                    .cachedb
                    .remove(format!("xsulib.authman.followers_count:{}", name))
                    .await;

                self.base
                    .cachedb
                    .remove(format!("xsulib.authman.following_count:{}", name))
                    .await;

                Ok(())
            }
            Err(_) => Err(AuthError::Other),
        }
    }

    /// Delete an existing [`Profile`] by its `username`
    pub async fn delete_profile_by_username(&self, name: String) -> Result<()> {
        let user = match self.get_profile_by_username(name.clone()).await {
            Ok(ua) => ua,
            Err(e) => return Err(e),
        };

        // make sure they aren't a manager
        let group = match self.get_group_by_id(user.group).await {
            Ok(g) => g,
            Err(_) => return Err(AuthError::Other),
        };

        if group.permissions.contains(&Permission::Manager) {
            return Err(AuthError::NotAllowed);
        }

        // delete
        self.delete_profile(name).await
    }

    /// Delete an existing [`Profile`] by its `username` and `password`
    pub async fn delete_profile_by_username_password(
        &self,
        name: String,
        password: String,
    ) -> Result<()> {
        let user = match self
            .get_profile_by_username_password(name.clone(), password.clone())
            .await
        {
            Ok(ua) => ua,
            Err(e) => return Err(e),
        };

        // make sure they aren't a manager
        let group = match self.get_group_by_id(user.group).await {
            Ok(g) => g,
            Err(_) => return Err(AuthError::Other),
        };

        if group.permissions.contains(&Permission::Manager) {
            return Err(AuthError::NotAllowed);
        }

        // delete
        self.delete_profile(name).await
    }

    // groups

    // GET
    /// Get a group by its id
    ///
    /// # Arguments:
    /// * `username` - `String` of the user's username
    pub async fn get_group_by_id(&self, id: i32) -> Result<Group> {
        // check in cache
        let cached = self
            .base
            .cachedb
            .get(format!("xsulib.authman.gid:{}", id))
            .await;

        if cached.is_some() {
            return Ok(serde_json::from_str::<Group>(cached.unwrap().as_str()).unwrap());
        }

        // ...
        let query: &str = if (self.base.db.r#type == "sqlite") | (self.base.db.r#type == "mysql") {
            "SELECT * FROM \"xgroups\" WHERE \"id\" = ?"
        } else {
            "SELECT * FROM \"xgroups\" WHERE \"id\" = $1"
        };

        let c = &self.base.db.client;
        let row = match sqlquery(query).bind::<&i32>(&id).fetch_one(c).await {
            Ok(r) => self.base.textify_row(r, Vec::new()).0,
            Err(_) => return Ok(Group::default()),
        };

        // store in cache
        let group = Group {
            name: row.get("name").unwrap().to_string(),
            id: row.get("id").unwrap().parse::<i32>().unwrap(),
            permissions: match serde_json::from_str(row.get("permissions").unwrap()) {
                Ok(m) => m,
                Err(_) => return Err(AuthError::ValueError),
            },
        };

        self.base
            .cachedb
            .set(
                format!("xsulib.authman.gid:{}", id),
                serde_json::to_string::<Group>(&group).unwrap(),
            )
            .await;

        // return
        Ok(group)
    }

    // profiles

    // GET
    /// Get an existing [`UserFollow`]
    ///
    /// # Arguments:
    /// * `user`
    /// * `following`
    pub async fn get_follow(&self, user: String, following: String) -> Result<UserFollow> {
        // fetch from database
        let query: &str = if (self.base.db.r#type == "sqlite") | (self.base.db.r#type == "mysql") {
            "SELECT * FROM \"xfollows\" WHERE \"user\" = ? AND \"following\" = ?"
        } else {
            "SELECT * FROM \"xfollows\" WHERE \"user\" = $1 AND \"following\" = $2"
        };

        let c = &self.base.db.client;
        let row = match sqlquery(query)
            .bind::<&String>(&user)
            .bind::<&String>(&following)
            .fetch_one(c)
            .await
        {
            Ok(u) => self.base.textify_row(u, Vec::new()).0,
            Err(_) => return Err(AuthError::Other),
        };

        // return
        Ok(UserFollow {
            user: row.get("user").unwrap().to_string(),
            following: row.get("following").unwrap().to_string(),
        })
    }

    /// Get all existing [`UserFollow`]s where `following` is the value of `user`
    ///
    /// # Arguments:
    /// * `user`
    pub async fn get_followers(&self, user: String) -> Result<Vec<UserFollow>> {
        // fetch from database
        let query: &str = if (self.base.db.r#type == "sqlite") | (self.base.db.r#type == "mysql") {
            "SELECT * FROM \"xfollows\" WHERE \"following\" = ?"
        } else {
            "SELECT * FROM \"xfollows\" WHERE \"following\" = $1"
        };

        let c = &self.base.db.client;
        let res = match sqlquery(query).bind::<&String>(&user).fetch_all(c).await {
            Ok(u) => {
                let mut out = Vec::new();

                for row in u {
                    let row = self.base.textify_row(row, Vec::new()).0;
                    out.push(UserFollow {
                        user: row.get("user").unwrap().to_string(),
                        following: row.get("following").unwrap().to_string(),
                    })
                }

                out
            }
            Err(_) => return Err(AuthError::Other),
        };

        // return
        Ok(res)
    }

    /// Get all existing [`UserFollow`]s where `following` is the value of `user`, 50 at a time
    ///
    /// # Arguments:
    /// * `user`
    /// * `page`
    pub async fn get_followers_paginated(
        &self,
        user: String,
        page: i32,
    ) -> Result<Vec<UserFollow>> {
        // fetch from database
        let query: String = if (self.base.db.r#type == "sqlite") | (self.base.db.r#type == "mysql")
        {
            format!(
                "SELECT * FROM \"xfollows\" WHERE \"following\" = ? LIMIT 50 OFFSET {}",
                page * 50
            )
        } else {
            format!(
                "SELECT * FROM \"xfollows\" WHERE \"following\" = $1 LIMIT 50 OFFSET {}",
                page * 50
            )
        };

        let c = &self.base.db.client;
        let res = match sqlquery(&query).bind::<&String>(&user).fetch_all(c).await {
            Ok(u) => {
                let mut out = Vec::new();

                for row in u {
                    let row = self.base.textify_row(row, Vec::new()).0;
                    out.push(UserFollow {
                        user: row.get("user").unwrap().to_string(),
                        following: row.get("following").unwrap().to_string(),
                    })
                }

                out
            }
            Err(_) => return Err(AuthError::Other),
        };

        // return
        Ok(res)
    }

    /// Get the number of followers `user` has
    ///
    /// # Arguments:
    /// * `user`
    pub async fn get_followers_count(&self, user: String) -> usize {
        // attempt to fetch from cache
        if let Some(count) = self
            .base
            .cachedb
            .get(format!("xsulib.authman.followers_count:{}", user))
            .await
        {
            return count.parse::<usize>().unwrap_or(0);
        };

        // fetch from database
        let count = self
            .get_followers(user.clone())
            .await
            .unwrap_or(Vec::new())
            .len();

        self.base
            .cachedb
            .set(
                format!("xsulib.authman.followers_count:{}", user),
                count.to_string(),
            )
            .await;

        count
    }

    /// Get all existing [`UserFollow`]s where `user` is the value of `user`
    ///
    /// # Arguments:
    /// * `user`
    pub async fn get_following(&self, user: String) -> Result<Vec<UserFollow>> {
        // fetch from database
        let query: &str = if (self.base.db.r#type == "sqlite") | (self.base.db.r#type == "mysql") {
            "SELECT * FROM \"xfollows\" WHERE \"user\" = ?"
        } else {
            "SELECT * FROM \"xfollows\" WHERE \"user\" = $1"
        };

        let c = &self.base.db.client;
        let res = match sqlquery(query).bind::<&String>(&user).fetch_all(c).await {
            Ok(u) => {
                let mut out = Vec::new();

                for row in u {
                    let row = self.base.textify_row(row, Vec::new()).0;
                    out.push(UserFollow {
                        user: row.get("user").unwrap().to_string(),
                        following: row.get("following").unwrap().to_string(),
                    })
                }

                out
            }
            Err(_) => return Err(AuthError::Other),
        };

        // return
        Ok(res)
    }

    /// Get all existing [`UserFollow`]s where `user` is the value of `user`, 50 at a time
    ///
    /// # Arguments:
    /// * `user`
    /// * `page`
    pub async fn get_following_paginated(
        &self,
        user: String,
        page: i32,
    ) -> Result<Vec<UserFollow>> {
        // fetch from database
        let query: String = if (self.base.db.r#type == "sqlite") | (self.base.db.r#type == "mysql")
        {
            format!(
                "SELECT * FROM \"xfollows\" WHERE \"user\" = ? LIMIT 50 OFFSET {}",
                page * 50
            )
        } else {
            format!(
                "SELECT * FROM \"xfollows\" WHERE \"user\" = $1 LIMIT 50 OFFSET {}",
                page * 50
            )
        };

        let c = &self.base.db.client;
        let res = match sqlquery(&query).bind::<&String>(&user).fetch_all(c).await {
            Ok(u) => {
                let mut out = Vec::new();

                for row in u {
                    let row = self.base.textify_row(row, Vec::new()).0;
                    out.push(UserFollow {
                        user: row.get("user").unwrap().to_string(),
                        following: row.get("following").unwrap().to_string(),
                    })
                }

                out
            }
            Err(_) => return Err(AuthError::Other),
        };

        // return
        Ok(res)
    }

    /// Get the number of users `user` is following
    ///
    /// # Arguments:
    /// * `user`
    pub async fn get_following_count(&self, user: String) -> usize {
        // attempt to fetch from cache
        if let Some(count) = self
            .base
            .cachedb
            .get(format!("xsulib.authman.following_count:{}", user))
            .await
        {
            return count.parse::<usize>().unwrap_or(0);
        };

        // fetch from database
        let count = self
            .get_following(user.clone())
            .await
            .unwrap_or(Vec::new())
            .len();

        self.base
            .cachedb
            .set(
                format!("xsulib.authman.following_count:{}", user),
                count.to_string(),
            )
            .await;

        count
    }

    // SET
    /// Toggle the following status of `user` on `following` ([`UserFollow`])
    ///
    /// # Arguments:
    /// * `props` - [`UserFollow`]
    pub async fn toggle_user_follow(&self, props: &mut UserFollow) -> Result<()> {
        // users cannot be the same
        if props.user == props.following {
            return Err(AuthError::Other);
        }

        // make sure both users exist
        if let Err(e) = self.get_profile_by_username(props.user.to_owned()).await {
            return Err(e);
        };

        // make sure both users exist
        if let Err(e) = self
            .get_profile_by_username(props.following.to_owned())
            .await
        {
            return Err(e);
        };

        // check if follow exists
        if let Ok(_) = self
            .get_follow(props.user.to_owned(), props.following.to_owned())
            .await
        {
            // delete
            let query: String =
                if (self.base.db.r#type == "sqlite") | (self.base.db.r#type == "mysql") {
                    "DELETE FROM \"xfollows\" WHERE \"user\" = ? AND \"following\" = ?"
                } else {
                    "DELETE FROM \"xfollows\" WHERE \"user\" = $1 AND \"following\" = $2"
                }
                .to_string();

            let c = &self.base.db.client;
            match sqlquery(&query)
                .bind::<&String>(&props.user)
                .bind::<&String>(&props.following)
                .execute(c)
                .await
            {
                Ok(_) => {
                    self.base
                        .cachedb
                        .decr(format!("xsulib.authman.following_count:{}", props.user))
                        .await;

                    self.base
                        .cachedb
                        .decr(format!(
                            "xsulib.authman.followers_count:{}",
                            props.following
                        ))
                        .await;

                    return Ok(());
                }
                Err(_) => return Err(AuthError::Other),
            };
        }

        // return
        let query: String = if (self.base.db.r#type == "sqlite") | (self.base.db.r#type == "mysql")
        {
            "INSERT INTO \"xfollows\" VALUES (?, ?)"
        } else {
            "INSERT INTO \"xfollows\" VALEUS ($1, $2)"
        }
        .to_string();

        let c = &self.base.db.client;
        match sqlquery(&query)
            .bind::<&String>(&props.user)
            .bind::<&String>(&props.following)
            .execute(c)
            .await
        {
            Ok(_) => {
                // bump counts
                self.base
                    .cachedb
                    .incr(format!("xsulib.authman.following_count:{}", props.user))
                    .await;

                self.base
                    .cachedb
                    .incr(format!(
                        "xsulib.authman.followers_count:{}",
                        props.following
                    ))
                    .await;

                // create notification
                if let Err(e) = self
                    .create_notification(NotificationCreate {
                        title: format!("[@{}](/@{}) followed you!", props.user, props.user),
                        content: String::new(),
                        address: format!("/@{}", props.user),
                        recipient: props.following.clone(),
                    })
                    .await
                {
                    return Err(e);
                };

                // return
                Ok(())
            }
            Err(_) => Err(AuthError::Other),
        }
    }

    // notifications

    // GET
    /// Get an existing notification
    ///
    /// ## Arguments:
    /// * `id`
    pub async fn get_notification(&self, id: String) -> Result<Notification> {
        // check in cache
        match self
            .base
            .cachedb
            .get(format!("xsulib.authman.notification:{}", id))
            .await
        {
            Some(c) => return Ok(serde_json::from_str::<Notification>(c.as_str()).unwrap()),
            None => (),
        };

        // pull from database
        let query: String = if (self.base.db.r#type == "sqlite") | (self.base.db.r#type == "mysql")
        {
            "SELECT * FROM \"xnotifications\" WHERE \"id\" = ?"
        } else {
            "SELECT * FROM \"xnotifications\" WHERE \"id\" = $1"
        }
        .to_string();

        let c = &self.base.db.client;
        let res = match sqlquery(&query).bind::<&String>(&id).fetch_one(c).await {
            Ok(p) => self.base.textify_row(p, Vec::new()).0,
            Err(_) => return Err(AuthError::NotFound),
        };

        // return
        let notification = Notification {
            title: res.get("title").unwrap().to_string(),
            content: res.get("content").unwrap().to_string(),
            address: res.get("address").unwrap().to_string(),
            timestamp: res.get("timestamp").unwrap().parse::<u128>().unwrap(),
            id: res.get("id").unwrap().to_string(),
            recipient: res.get("recipient").unwrap().to_string(),
        };

        // store in cache
        self.base
            .cachedb
            .set(
                format!("xsulib.authman.notification:{}", id),
                serde_json::to_string::<Notification>(&notification).unwrap(),
            )
            .await;

        // return
        Ok(notification)
    }

    /// Get all notifications by their recipient
    ///
    /// ## Arguments:
    /// * `recipient`
    pub async fn get_notifications_by_recipient(
        &self,
        recipient: String,
    ) -> Result<Vec<Notification>> {
        // pull from database
        let query: String = if (self.base.db.r#type == "sqlite") | (self.base.db.r#type == "mysql")
        {
            "SELECT * FROM \"xnotifications\" WHERE \"recipient\" = ? ORDER BY \"timestamp\" DESC"
        } else {
            "SELECT * FROM \"xnotifications\" WHERE \"recipient\" = $1 ORDER BY \"timestamp\" DESC"
        }
        .to_string();

        let c = &self.base.db.client;
        let res = match sqlquery(&query)
            .bind::<&String>(&recipient.to_lowercase())
            .fetch_all(c)
            .await
        {
            Ok(p) => {
                let mut out: Vec<Notification> = Vec::new();

                for row in p {
                    let res = self.base.textify_row(row, Vec::new()).0;
                    out.push(Notification {
                        title: res.get("title").unwrap().to_string(),
                        content: res.get("content").unwrap().to_string(),
                        address: res.get("address").unwrap().to_string(),
                        timestamp: res.get("timestamp").unwrap().parse::<u128>().unwrap(),
                        id: res.get("id").unwrap().to_string(),
                        recipient: res.get("recipient").unwrap().to_string(),
                    });
                }

                out
            }
            Err(_) => return Err(AuthError::NotFound),
        };

        // return
        Ok(res)
    }

    /// Get the number of notifications by their recipient
    ///
    /// ## Arguments:
    /// * `recipient`
    pub async fn get_notification_count_by_recipient(&self, recipient: String) -> usize {
        // attempt to fetch from cache
        if let Some(count) = self
            .base
            .cachedb
            .get(format!("xsulib.authman.notification_count:{}", recipient))
            .await
        {
            return count.parse::<usize>().unwrap_or(0);
        };

        // fetch from database
        let count = self
            .get_notifications_by_recipient(recipient.clone())
            .await
            .unwrap_or(Vec::new())
            .len();

        self.base
            .cachedb
            .set(
                format!("xsulib.authman.notification_count:{}", recipient),
                count.to_string(),
            )
            .await;

        count
    }

    // SET
    /// Create a new notification
    ///
    /// ## Arguments:
    /// * `props` - [`QuestionCreate`]
    pub async fn create_notification(&self, props: NotificationCreate) -> Result<()> {
        let notification = Notification {
            title: props.title,
            content: props.content,
            address: props.address,
            timestamp: utility::unix_epoch_timestamp(),
            id: utility::random_id(),
            recipient: props.recipient,
        };

        // create notification
        let query: String = if (self.base.db.r#type == "sqlite") | (self.base.db.r#type == "mysql")
        {
            "INSERT INTO \"xnotifications\" VALUES (?, ?, ?, ?, ?, ?)"
        } else {
            "INSERT INTO \"xnotifications\" VALEUS ($1, $2, $3, $4, $5, $6)"
        }
        .to_string();

        let c = &self.base.db.client;
        match sqlquery(&query)
            .bind::<&String>(&notification.title)
            .bind::<&String>(&notification.content)
            .bind::<&String>(&notification.address)
            .bind::<&String>(&notification.timestamp.to_string())
            .bind::<&String>(&notification.id)
            .bind::<&String>(&notification.recipient)
            .execute(c)
            .await
        {
            Ok(_) => {
                // incr notifications count
                self.base
                    .cachedb
                    .incr(format!(
                        "xsulib.authman.notification_count:{}",
                        notification.recipient
                    ))
                    .await;

                // ...
                return Ok(());
            }
            Err(_) => return Err(AuthError::Other),
        };
    }

    /// Delete an existing notification
    ///
    /// Notifications can only be deleted by their recipient.
    ///
    /// ## Arguments:
    /// * `id` - the ID of the notification
    /// * `user` - the user doing this
    pub async fn delete_notification(&self, id: String, user: Profile) -> Result<()> {
        // make sure notification exists
        let notification = match self.get_notification(id.clone()).await {
            Ok(n) => n,
            Err(e) => return Err(e),
        };

        // check username
        if user.username != notification.recipient {
            // check permission
            let group = match self.get_group_by_id(user.group).await {
                Ok(g) => g,
                Err(_) => return Err(AuthError::Other),
            };

            if !group.permissions.contains(&Permission::Manager) {
                return Err(AuthError::NotAllowed);
            }
        }

        // delete notification
        let query: String = if (self.base.db.r#type == "sqlite") | (self.base.db.r#type == "mysql")
        {
            "DELETE FROM \"xnotifications\" WHERE \"id\" = ?"
        } else {
            "DELETE FROM \"xnotifications\" WHERE \"id\" = $1"
        }
        .to_string();

        let c = &self.base.db.client;
        match sqlquery(&query).bind::<&String>(&id).execute(c).await {
            Ok(_) => {
                // decr notifications count
                self.base
                    .cachedb
                    .decr(format!(
                        "xsulib.authman.notification_count:{}",
                        notification.recipient
                    ))
                    .await;

                // remove from cache
                self.base
                    .cachedb
                    .remove(format!("xsulib.authman.notification:{}", id))
                    .await;

                // return
                return Ok(());
            }
            Err(_) => return Err(AuthError::Other),
        };
    }

    /// Delete all existing notifications by their recipient
    ///
    /// ## Arguments:
    /// * `id` - the ID of the notification
    /// * `user` - the user doing this
    pub async fn delete_notifications_by_recipient(
        &self,
        recipient: String,
        user: Profile,
    ) -> Result<()> {
        // make sure notifications exists
        let notifications = match self.get_notifications_by_recipient(recipient.clone()).await {
            Ok(n) => n,
            Err(e) => return Err(e),
        };

        // check username
        if user.username != recipient {
            // check permission
            let group = match self.get_group_by_id(user.group).await {
                Ok(g) => g,
                Err(_) => return Err(AuthError::Other),
            };

            if !group.permissions.contains(&Permission::Manager) {
                return Err(AuthError::NotAllowed);
            }
        }

        // delete notifications
        let query: String = if (self.base.db.r#type == "sqlite") | (self.base.db.r#type == "mysql")
        {
            "DELETE FROM \"xnotifications\" WHERE \"recipient\" = ?"
        } else {
            "DELETE FROM \"xnotifications\" WHERE \"recipient\" = $1"
        }
        .to_string();

        let c = &self.base.db.client;
        match sqlquery(&query)
            .bind::<&String>(&recipient)
            .execute(c)
            .await
        {
            Ok(_) => {
                // clear notifications count
                self.base
                    .cachedb
                    .remove(format!("xsulib.authman.notification_count:{}", recipient))
                    .await;

                // clear cache for all deleted notifications
                for notification in notifications {
                    // remove from cache
                    self.base
                        .cachedb
                        .remove(format!("xsulib.authman.notification:{}", notification.id))
                        .await;
                }

                // return
                return Ok(());
            }
            Err(_) => return Err(AuthError::Other),
        };
    }
}
