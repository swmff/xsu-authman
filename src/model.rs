use hcaptcha::Hcaptcha;
use std::collections::HashMap;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use serde::{Deserialize, Serialize};
use xsu_dataman::DefaultReturn;
use xsu_util::ui::BlockList;

/// Basic user structure
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Profile {
    /// User ID
    pub id: String,
    /// User name
    pub username: String,
    /// Hashed user password
    pub password: String,
    /// User password salt
    pub salt: String,
    /// User login tokens
    pub tokens: Vec<String>,
    /// User IPs (these line up with the tokens in `tokens`)
    pub ips: Vec<String>,
    /// Extra user information
    pub metadata: ProfileMetadata,
    /// User badges
    ///
    /// Vec<(Text, Background, Text Color)>
    pub badges: Vec<(String, String, String)>,
    /// User group
    pub group: i32,
    /// User join timestamp
    pub joined: u128,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            id: String::new(),
            username: String::new(),
            password: String::new(),
            salt: String::new(),
            tokens: Vec::new(),
            ips: Vec::new(),
            metadata: ProfileMetadata::default(),
            badges: Vec::new(),
            group: 0,
            joined: xsu_dataman::utility::unix_epoch_timestamp(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProfileMetadata {
    /// A URL which dictates where the user's profile avatar is loaded from, `xsu-cliff` proxies this link and returns the user avatar
    #[serde(default)]
    pub avatar_url: String,
    /// The user profile's [`BlockList`]
    #[serde(default)]
    pub definition: BlockList,
    /// Extra key-value pairs
    #[serde(default)]
    pub kv: HashMap<String, String>,
}

impl Default for ProfileMetadata {
    fn default() -> Self {
        Self {
            avatar_url: String::new(),
            definition: BlockList::default(),
            kv: HashMap::new(),
        }
    }
}

/// Basic follow structure
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserFollow {
    /// The ID of the user following
    pub user: String,
    /// The ID of the user they are following
    pub following: String,
}

/// Basic notification structure
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Notification {
    /// The title of the notification
    pub title: String,
    /// The content of the notification
    pub content: String,
    /// The address of the notification (where it goes)
    pub address: String,
    /// The timestamp of when the notification was created
    pub timestamp: u128,
    /// The ID of the notification
    pub id: String,
    /// The recipient of the notification
    pub recipient: String,
}

/// Basic warning structure
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Warning {
    /// The ID of the warning
    pub id: String,
    /// The content of the warning
    pub content: String,
    /// The timestamp of when the warning was created
    pub timestamp: u128,
    /// The recipient of the warning
    pub recipient: String,
    /// The moderator who warned the recipient
    pub moderator: Profile,
}

/// Basic IP ban
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IpBan {
    /// The ID of the ban
    pub id: String,
    /// The IP that was banned
    pub ip: String,
    /// The reason for the ban
    pub reason: String,
    /// The user that banned this IP
    pub moderator: Profile,
    /// The timestamp of when the ban was created
    pub timestamp: u128,
}

/// xsu system permission
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Permission {
    /// Permission to manage the server and managers
    Admin,
    /// Permission to manage the server and assets
    Manager,
    /// Permission to create warnings and do small moderator tasks
    Helper,
}

/// Basic permission group
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Group {
    pub name: String,
    pub id: i32,
    pub permissions: Vec<Permission>,
}

impl Default for Group {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            id: 0,
            permissions: Vec::new(),
        }
    }
}

// props
#[derive(Serialize, Deserialize, Debug, Hcaptcha)]
pub struct ProfileCreate {
    pub username: String,
    pub password: String,
    #[captcha]
    pub token: String,
}

#[derive(Serialize, Deserialize, Debug, Hcaptcha)]
pub struct ProfileLogin {
    pub username: String,
    pub password: String,
    #[captcha]
    pub token: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SetProfileMetadata {
    pub metadata: ProfileMetadata,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SetProfileBadges {
    pub badges: Vec<(String, String, String)>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SetProfileGroup {
    pub group: i32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SetProfilePassword {
    pub password: String,
    pub new_password: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SetProfileUsername {
    pub password: String,
    pub new_name: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NotificationCreate {
    pub title: String,
    pub content: String,
    pub address: String,
    pub recipient: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WarningCreate {
    pub content: String,
    pub recipient: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IpBanCreate {
    pub ip: String,
    pub reason: String,
}

/// General API errors
#[derive(Debug)]
pub enum AuthError {
    MustBeUnique,
    NotAllowed,
    ValueError,
    NotFound,
    Other,
}

impl AuthError {
    pub fn to_string(&self) -> String {
        use AuthError::*;
        match self {
            MustBeUnique => String::from("One of the given values must be unique."),
            NotAllowed => String::from("You are not allowed to access this resource."),
            ValueError => String::from("One of the field values given is invalid."),
            NotFound => String::from("No asset with this ID could be found."),
            _ => String::from("An unspecified error has occured"),
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        use crate::model::AuthError::*;
        match self {
            NotAllowed => (
                StatusCode::UNAUTHORIZED,
                Json(DefaultReturn::<u16> {
                    success: false,
                    message: self.to_string(),
                    payload: 401,
                }),
            )
                .into_response(),
            NotFound => (
                StatusCode::NOT_FOUND,
                Json(DefaultReturn::<u16> {
                    success: false,
                    message: self.to_string(),
                    payload: 404,
                }),
            )
                .into_response(),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(DefaultReturn::<u16> {
                    success: false,
                    message: self.to_string(),
                    payload: 500,
                }),
            )
                .into_response(),
        }
    }
}
