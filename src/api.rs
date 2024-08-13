//! Responds to API requests
use crate::database::Database;
use crate::model::{
    AuthError, Permission, ProfileCreate, ProfileLogin, SetProfileGroup, SetProfileMetadata,
    SetProfilePassword, UserFollow,
};
use axum::body::Bytes;
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use xsu_dataman::DefaultReturn;

use axum::response::IntoResponse;
use axum::{
    extract::{Path, Query, State},
    routing::{get, post, delete},
    Json, Router,
};
use axum_extra::extract::cookie::CookieJar;

pub fn routes(database: Database) -> Router {
    Router::new()
        // profiles
        .route("/profile/:username/group", post(set_group_request))
        .route("/profile/:username/password", post(set_password_request))
        .route("/profile/:username/metadata", post(update_metdata_request))
        .route("/profile/:username/avatar", get(profile_avatar_request))
        .route("/profile/:username/follow", get(profile_follow_request))
        .route("/profile/:username", delete(delete_other_request))
        .route("/profile/:username", get(profile_inspect_request))
        // notifications
        .route("/notifications/:id", delete(delete_notification_request))
        .route(
            "/notifications/clear",
            delete(delete_all_notifications_request),
        )
        // me
        .route("/me/delete", post(delete_me_request))
        .route("/me", get(me_request))
        // account
        .route("/register", post(create_profile_request))
        .route("/login", post(login_request))
        .route("/callback", get(callback_request))
        .route("/logout", post(logout_request))
        // ...
        .with_state(database)
}

/// [`Database::create_profile`]
pub async fn create_profile_request(
    jar: CookieJar,
    State(database): State<Database>,
    Json(props): Json<ProfileCreate>,
) -> impl IntoResponse {
    if let Some(_) = jar.get("__Secure-Token") {
        return (
            HeaderMap::new(),
            serde_json::to_string(&DefaultReturn {
                success: false,
                message: AuthError::NotAllowed.to_string(),
                payload: (),
            })
            .unwrap(),
        );
    }

    let res = match database
        .create_profile(props.username, props.password)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return (
                HeaderMap::new(),
                serde_json::to_string(&DefaultReturn {
                    success: false,
                    message: e.to_string(),
                    payload: (),
                })
                .unwrap(),
            );
        }
    };

    // return
    let mut headers = HeaderMap::new();

    headers.insert(
        "Set-Cookie",
        format!(
            "__Secure-Token={}; SameSite=Lax; Secure; Path=/; HostOnly=true; HttpOnly=true; Max-Age={}",
            res,
            60* 60 * 24 * 365
        )
        .parse()
        .unwrap(),
    );

    (
        headers,
        serde_json::to_string(&DefaultReturn {
            success: true,
            message: res.clone(),
            payload: (),
        })
        .unwrap(),
    )
}

/// [`Database::get_profile_by_username_password`]
pub async fn login_request(
    State(database): State<Database>,
    Json(props): Json<ProfileLogin>,
) -> impl IntoResponse {
    let mut ua = match database
        .get_profile_by_username_password(props.username.clone(), props.password.clone())
        .await
    {
        Ok(ua) => ua,
        Err(e) => {
            return (
                HeaderMap::new(),
                serde_json::to_string(&DefaultReturn {
                    success: false,
                    message: e.to_string(),
                    payload: (),
                })
                .unwrap(),
            )
        }
    };

    let token = xsu_dataman::utility::uuid();
    let token_hashed = xsu_dataman::utility::hash(token.clone());

    ua.tokens.push(token_hashed);
    database
        .edit_profile_tokens_by_name(props.username.clone(), ua.tokens)
        .await
        .unwrap();

    // return
    let mut headers = HeaderMap::new();

    headers.insert(
        "Set-Cookie",
        format!(
            "__Secure-Token={}; SameSite=Lax; Secure; Path=/; HostOnly=true; HttpOnly=true; Max-Age={}",
            token,
            60* 60 * 24 * 365
        )
        .parse()
        .unwrap(),
    );

    (
        headers,
        serde_json::to_string(&DefaultReturn {
            success: true,
            message: token,
            payload: (),
        })
        .unwrap(),
    )
}

/// Delete a notification
pub async fn delete_notification_request(
    jar: CookieJar,
    Path(id): Path<String>,
    State(database): State<Database>,
) -> impl IntoResponse {
    // get user from token
    let auth_user = match jar.get("__Secure-Token") {
        Some(c) => match database
            .get_profile_by_unhashed(c.value_trimmed().to_string())
            .await
        {
            Ok(ua) => ua,
            Err(e) => {
                return Json(DefaultReturn {
                    success: false,
                    message: e.to_string(),
                    payload: (),
                });
            }
        },
        None => {
            return Json(DefaultReturn {
                success: false,
                message: AuthError::NotAllowed.to_string(),
                payload: (),
            });
        }
    };

    // return
    if let Err(e) = database.delete_notification(id, auth_user).await {
        return Json(DefaultReturn {
            success: false,
            message: e.to_string(),
            payload: (),
        });
    }

    Json(DefaultReturn {
        success: true,
        message: "Notification deleted".to_string(),
        payload: (),
    })
}

/// Delete the current user's notifications
pub async fn delete_all_notifications_request(
    jar: CookieJar,
    State(database): State<Database>,
) -> impl IntoResponse {
    // get user from token
    let auth_user = match jar.get("__Secure-Token") {
        Some(c) => match database
            .get_profile_by_unhashed(c.value_trimmed().to_string())
            .await
        {
            Ok(ua) => ua,
            Err(e) => {
                return Json(DefaultReturn {
                    success: false,
                    message: e.to_string(),
                    payload: (),
                });
            }
        },
        None => {
            return Json(DefaultReturn {
                success: false,
                message: AuthError::NotAllowed.to_string(),
                payload: (),
            });
        }
    };

    // return
    if let Err(e) = database
        .delete_notifications_by_recipient(auth_user.username.clone(), auth_user)
        .await
    {
        return Json(DefaultReturn {
            success: false,
            message: e.to_string(),
            payload: (),
        });
    }

    Json(DefaultReturn {
        success: true,
        message: "Notifications cleared!".to_string(),
        payload: (),
    })
}

/// Returns the current user's username
pub async fn me_request(jar: CookieJar, State(database): State<Database>) -> impl IntoResponse {
    // get user from token
    let auth_user = match jar.get("__Secure-Token") {
        Some(c) => match database
            .get_profile_by_unhashed(c.value_trimmed().to_string())
            .await
        {
            Ok(ua) => ua,
            Err(e) => {
                return Json(DefaultReturn {
                    success: false,
                    message: e.to_string(),
                    payload: (),
                });
            }
        },
        None => {
            return Json(DefaultReturn {
                success: false,
                message: AuthError::NotAllowed.to_string(),
                payload: (),
            });
        }
    };

    // return
    Json(DefaultReturn {
        success: true,
        message: auth_user.username,
        payload: (),
    })
}

#[derive(Serialize, Deserialize)]
pub struct DeleteProfile {
    password: String,
}

/// Delete the current user's profile
pub async fn delete_me_request(
    jar: CookieJar,
    State(database): State<Database>,
    Json(req): Json<DeleteProfile>,
) -> impl IntoResponse {
    // get user from token
    let auth_user = match jar.get("__Secure-Token") {
        Some(c) => match database
            .get_profile_by_unhashed(c.value_trimmed().to_string())
            .await
        {
            Ok(ua) => ua,
            Err(e) => {
                return Json(DefaultReturn {
                    success: false,
                    message: e.to_string(),
                    payload: (),
                });
            }
        },
        None => {
            return Json(DefaultReturn {
                success: false,
                message: AuthError::NotAllowed.to_string(),
                payload: (),
            });
        }
    };

    // return
    if let Err(e) = database
        .delete_profile_by_username_password(auth_user.username, req.password)
        .await
    {
        return Json(DefaultReturn {
            success: false,
            message: e.to_string(),
            payload: (),
        });
    }

    Json(DefaultReturn {
        success: true,
        message: "Profile deleted, goodbye!".to_string(),
        payload: (),
    })
}

/// Get a profile's avatar image
pub async fn profile_avatar_request(
    Path(username): Path<String>,
    State(database): State<Database>,
) -> impl IntoResponse {
    // get user
    let auth_user = match database.get_profile_by_username(username).await {
        Ok(ua) => ua,
        Err(_) => {
            return Bytes::from_static(&[0x0u8]);
        }
    };

    // get profile image
    if auth_user.metadata.avatar_url.is_empty() {
        return Bytes::from_static(&[0]);
    }

    match database
        .http
        .get(auth_user.metadata.avatar_url)
        .send()
        .await
    {
        Ok(r) => r.bytes().await.unwrap(),
        Err(_) => Bytes::from_static(&[0x0u8]),
    }
}

/// View a profile's information
pub async fn profile_inspect_request(
    Path(username): Path<String>,
    State(database): State<Database>,
) -> impl IntoResponse {
    // get user
    let mut auth_user = match database.get_profile_by_username(username).await {
        Ok(ua) => ua,
        Err(e) => {
            return Json(DefaultReturn {
                success: false,
                message: e.to_string(),
                payload: None,
            });
        }
    };

    // edit profile
    auth_user.id = String::new();
    auth_user.tokens = Vec::new();

    // return
    Json(DefaultReturn {
        success: true,
        message: auth_user.username.to_string(),
        payload: Some(auth_user),
    })
}

/// Change a profile's group
pub async fn set_group_request(
    jar: CookieJar,
    Path(username): Path<String>,
    State(database): State<Database>,
    Json(props): Json<SetProfileGroup>,
) -> impl IntoResponse {
    // get user from token
    let auth_user = match jar.get("__Secure-Token") {
        Some(c) => match database
            .get_profile_by_unhashed(c.value_trimmed().to_string())
            .await
        {
            Ok(ua) => ua,
            Err(e) => {
                return Json(DefaultReturn {
                    success: false,
                    message: e.to_string(),
                    payload: None,
                });
            }
        },
        None => {
            return Json(DefaultReturn {
                success: false,
                message: AuthError::NotAllowed.to_string(),
                payload: None,
            });
        }
    };

    // check permission
    let group = match database.get_group_by_id(auth_user.group).await {
        Ok(g) => g,
        Err(e) => {
            return Json(DefaultReturn {
                success: false,
                message: e.to_string(),
                payload: None,
            })
        }
    };

    if !group.permissions.contains(&Permission::Manager) {
        // we must have the "Manager" permission to edit other users
        return Json(DefaultReturn {
            success: false,
            message: AuthError::NotAllowed.to_string(),
            payload: None,
        });
    }

    // get other user
    let other_user = match database.get_profile_by_username(username.clone()).await {
        Ok(ua) => ua,
        Err(e) => {
            return Json(DefaultReturn {
                success: false,
                message: e.to_string(),
                payload: None,
            });
        }
    };

    // check permission
    let group = match database.get_group_by_id(other_user.group).await {
        Ok(g) => g,
        Err(e) => {
            return Json(DefaultReturn {
                success: false,
                message: e.to_string(),
                payload: None,
            })
        }
    };

    if group.permissions.contains(&Permission::Manager) {
        // we cannot manager other managers
        return Json(DefaultReturn {
            success: false,
            message: AuthError::NotAllowed.to_string(),
            payload: None,
        });
    }

    // push update
    // TODO: try not to clone
    if let Err(e) = database
        .edit_profile_group_by_name(username, props.group)
        .await
    {
        return Json(DefaultReturn {
            success: false,
            message: e.to_string(),
            payload: None,
        });
    }

    // return
    Json(DefaultReturn {
        success: true,
        message: "Acceptable".to_string(),
        payload: Some(props.group),
    })
}

/// Change a profile's password
pub async fn set_password_request(
    jar: CookieJar,
    Path(username): Path<String>,
    State(database): State<Database>,
    Json(props): Json<SetProfilePassword>,
) -> impl IntoResponse {
    // get user from token
    let auth_user = match jar.get("__Secure-Token") {
        Some(c) => match database
            .get_profile_by_unhashed(c.value_trimmed().to_string())
            .await
        {
            Ok(ua) => ua,
            Err(e) => {
                return Json(DefaultReturn {
                    success: false,
                    message: e.to_string(),
                    payload: None,
                });
            }
        },
        None => {
            return Json(DefaultReturn {
                success: false,
                message: AuthError::NotAllowed.to_string(),
                payload: None,
            });
        }
    };

    // check permission
    if auth_user.username != username {
        let group = match database.get_group_by_id(auth_user.group).await {
            Ok(g) => g,
            Err(e) => {
                return Json(DefaultReturn {
                    success: false,
                    message: e.to_string(),
                    payload: None,
                })
            }
        };

        if !group.permissions.contains(&Permission::Manager) {
            // we must have the "Manager" permission to edit other users
            return Json(DefaultReturn {
                success: false,
                message: AuthError::NotAllowed.to_string(),
                payload: None,
            });
        }

        // get other user
        let other_user = match database.get_profile_by_username(username.clone()).await {
            Ok(ua) => ua,
            Err(e) => {
                return Json(DefaultReturn {
                    success: false,
                    message: e.to_string(),
                    payload: None,
                });
            }
        };

        // check permission
        let group = match database.get_group_by_id(other_user.group).await {
            Ok(g) => g,
            Err(e) => {
                return Json(DefaultReturn {
                    success: false,
                    message: e.to_string(),
                    payload: None,
                })
            }
        };

        if group.permissions.contains(&Permission::Manager) {
            // we cannot manager other managers
            return Json(DefaultReturn {
                success: false,
                message: AuthError::NotAllowed.to_string(),
                payload: None,
            });
        }
    }

    // check user permissions
    // returning NotAllowed here will block them from editing their profile
    // we don't want to waste resources on rule breakers
    if auth_user.group == -1 {
        // group -1 (even if it exists) is for marking users as banned
        return Json(DefaultReturn {
            success: false,
            message: AuthError::NotAllowed.to_string(),
            payload: None,
        });
    }

    // push update
    // TODO: try not to clone
    if let Err(e) = database
        .edit_profile_password_by_name(username, props.password, props.new_password.clone())
        .await
    {
        return Json(DefaultReturn {
            success: false,
            message: e.to_string(),
            payload: None,
        });
    }

    // return
    Json(DefaultReturn {
        success: true,
        message: "Acceptable".to_string(),
        payload: Some(props.new_password),
    })
}

/// Update a user's metadata
pub async fn update_metdata_request(
    jar: CookieJar,
    Path(username): Path<String>,
    State(database): State<Database>,
    Json(props): Json<SetProfileMetadata>,
) -> impl IntoResponse {
    // get user from token
    let auth_user = match jar.get("__Secure-Token") {
        Some(c) => match database
            .get_profile_by_unhashed(c.value_trimmed().to_string())
            .await
        {
            Ok(ua) => ua,
            Err(e) => {
                return Json(DefaultReturn {
                    success: false,
                    message: e.to_string(),
                    payload: (),
                });
            }
        },
        None => {
            return Json(DefaultReturn {
                success: false,
                message: AuthError::NotAllowed.to_string(),
                payload: (),
            });
        }
    };

    // check permission
    if auth_user.username != username {
        let group = match database.get_group_by_id(auth_user.group).await {
            Ok(g) => g,
            Err(e) => {
                return Json(DefaultReturn {
                    success: false,
                    message: e.to_string(),
                    payload: (),
                })
            }
        };

        if !group.permissions.contains(&Permission::Manager) {
            // we must have the "Manager" permission to edit other users
            return Json(DefaultReturn {
                success: false,
                message: AuthError::NotAllowed.to_string(),
                payload: (),
            });
        }

        // get other user
        let other_user = match database.get_profile_by_username(username.clone()).await {
            Ok(ua) => ua,
            Err(e) => {
                return Json(DefaultReturn {
                    success: false,
                    message: e.to_string(),
                    payload: (),
                });
            }
        };

        // check permission
        let group = match database.get_group_by_id(other_user.group).await {
            Ok(g) => g,
            Err(e) => {
                return Json(DefaultReturn {
                    success: false,
                    message: e.to_string(),
                    payload: (),
                })
            }
        };

        if group.permissions.contains(&Permission::Manager) {
            // we cannot manager other managers
            return Json(DefaultReturn {
                success: false,
                message: AuthError::NotAllowed.to_string(),
                payload: (),
            });
        }
    }

    // check user permissions
    // returning NotAllowed here will block them from editing their profile
    // we don't want to waste resources on rule breakers
    if auth_user.group == -1 {
        // group -1 (even if it exists) is for marking users as banned
        return Json(DefaultReturn {
            success: false,
            message: AuthError::NotAllowed.to_string(),
            payload: (),
        });
    }

    // return
    match database
        .edit_profile_metadata_by_name(username, props.metadata)
        .await
    {
        Ok(_) => Json(DefaultReturn {
            success: true,
            message: "Acceptable".to_string(),
            payload: (),
        }),
        Err(e) => Json(DefaultReturn {
            success: false,
            message: e.to_string(),
            payload: (),
        }),
    }
}

/// Toggle following on the given user
pub async fn profile_follow_request(
    jar: CookieJar,
    Path(username): Path<String>,
    State(database): State<Database>,
) -> impl IntoResponse {
    // get user from token
    let auth_user = match jar.get("__Secure-Token") {
        Some(c) => match database
            .get_profile_by_unhashed(c.value_trimmed().to_string())
            .await
        {
            Ok(ua) => ua,
            Err(e) => {
                return Json(DefaultReturn {
                    success: false,
                    message: e.to_string(),
                    payload: (),
                });
            }
        },
        None => {
            return Json(DefaultReturn {
                success: false,
                message: AuthError::NotAllowed.to_string(),
                payload: (),
            });
        }
    };

    // return
    match database
        .toggle_user_follow(&mut UserFollow {
            user: auth_user.username,
            following: username,
        })
        .await
    {
        Ok(_) => Json(DefaultReturn {
            success: true,
            message: "Acceptable".to_string(),
            payload: (),
        }),
        Err(e) => Json(DefaultReturn {
            success: false,
            message: e.to_string(),
            payload: (),
        }),
    }
}

/// Delete another user
pub async fn delete_other_request(
    jar: CookieJar,
    Path(username): Path<String>,
    State(database): State<Database>,
) -> impl IntoResponse {
    // get user from token
    let auth_user = match jar.get("__Secure-Token") {
        Some(c) => match database
            .get_profile_by_unhashed(c.value_trimmed().to_string())
            .await
        {
            Ok(ua) => ua,
            Err(e) => {
                return Json(DefaultReturn {
                    success: false,
                    message: e.to_string(),
                    payload: (),
                });
            }
        },
        None => {
            return Json(DefaultReturn {
                success: false,
                message: AuthError::NotAllowed.to_string(),
                payload: (),
            });
        }
    };

    // check permission
    if auth_user.username != username {
        let group = match database.get_group_by_id(auth_user.group).await {
            Ok(g) => g,
            Err(e) => {
                return Json(DefaultReturn {
                    success: false,
                    message: e.to_string(),
                    payload: (),
                })
            }
        };

        if !group.permissions.contains(&Permission::Manager) {
            // we must have the "Manager" permission to edit other users
            return Json(DefaultReturn {
                success: false,
                message: AuthError::NotAllowed.to_string(),
                payload: (),
            });
        }

        // get other user
        let other_user = match database.get_profile_by_username(username.clone()).await {
            Ok(ua) => ua,
            Err(e) => {
                return Json(DefaultReturn {
                    success: false,
                    message: e.to_string(),
                    payload: (),
                });
            }
        };

        // check permission
        let group = match database.get_group_by_id(other_user.group).await {
            Ok(g) => g,
            Err(e) => {
                return Json(DefaultReturn {
                    success: false,
                    message: e.to_string(),
                    payload: (),
                })
            }
        };

        if group.permissions.contains(&Permission::Manager) {
            // we cannot manager other managers
            return Json(DefaultReturn {
                success: false,
                message: AuthError::NotAllowed.to_string(),
                payload: (),
            });
        }
    }

    // check user permissions
    // returning NotAllowed here will block them from editing their profile
    // we don't want to waste resources on rule breakers
    if auth_user.group == -1 {
        // group -1 (even if it exists) is for marking users as banned
        return Json(DefaultReturn {
            success: false,
            message: AuthError::NotAllowed.to_string(),
            payload: (),
        });
    }

    // return
    match database.delete_profile_by_username(username).await {
        Ok(_) => Json(DefaultReturn {
            success: true,
            message: "Acceptable".to_string(),
            payload: (),
        }),
        Err(e) => Json(DefaultReturn {
            success: false,
            message: e.to_string(),
            payload: (),
        }),
    }
}

// general
pub async fn not_found() -> impl IntoResponse {
    Json(DefaultReturn::<u16> {
        success: false,
        message: String::from("Path does not exist"),
        payload: 404,
    })
}

// auth
#[derive(serde::Deserialize)]
pub struct CallbackQueryProps {
    pub uid: String, // this uid will need to be sent to the client as a token
}

pub async fn callback_request(Query(params): Query<CallbackQueryProps>) -> impl IntoResponse {
    // return
    (
        [
            ("Content-Type".to_string(), "text/html".to_string()),
            (
                "Set-Cookie".to_string(),
                format!(
                    "__Secure-Token={}; SameSite=Lax; Secure; Path=/; HostOnly=true; HttpOnly=true; Max-Age={}",
                    params.uid,
                    60 * 60 * 24 * 365
                ),
            ),
        ],
        "<head>
            <meta http-equiv=\"Refresh\" content=\"0; URL=/\" />
        </head>"
    )
}

pub async fn logout_request(jar: CookieJar) -> impl IntoResponse {
    // check for cookie
    if let Some(_) = jar.get("__Secure-Token") {
        return (
            [
                ("Content-Type".to_string(), "text/plain".to_string()),
                (
                    "Set-Cookie".to_string(),
                   "__Secure-Token=refresh; SameSite=Strict; Secure; Path=/; HostOnly=true; HttpOnly=true; Max-Age=0".to_string(),
                ),
            ],
            "You have been signed out. You can now close this tab.",
        );
    }

    // return
    (
        [
            ("Content-Type".to_string(), "text/plain".to_string()),
            ("Set-Cookie".to_string(), String::new()),
        ],
        "Failed to sign out of account.",
    )
}
