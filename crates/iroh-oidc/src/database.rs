use sqlx::sqlite::SqlitePoolOptions;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Database {
    pool: sqlx::SqlitePool,
}

pub struct DeviceCode {
    pub device_code_hash: Vec<u8>,
    pub user_code_hash: Vec<u8>,
    pub expires_at: i64,
    pub user_id: Option<Uuid>,
    pub is_used: bool,
    pub device_name_hint: Option<String>,
    pub device_ip_hint: Option<String>,
}

pub struct AuthCode {
    pub auth_code_hash: Vec<u8>,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: Vec<u8>,
    pub expires_at: i64,
    pub user_id: Uuid,
    pub is_used: bool,
    pub device_name: Option<String>,
}

pub struct Session {
    pub id: Uuid,
    pub token_hash: Vec<u8>,
    pub last_used_at: i64,
    pub user_id: Uuid,
    pub device_name: Option<String>,
}

pub struct User {
    pub id: Uuid,
}

impl Database {
    pub async fn open_memory() -> anyhow::Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect("sqlite::memory:")
            .await?;

        let db = Database { pool };
        db.migrate().await?;

        Ok(db)
    }

    pub async fn open_file(path: &str) -> anyhow::Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&format!("sqlite://{}", path))
            .await?;

        let db = Database { pool };
        db.migrate().await?;

        Ok(db)
    }

    async fn migrate(&self) -> anyhow::Result<()> {
        sqlx::migrate!("./migrations").run(&self.pool).await?;

        Ok(())
    }

    pub async fn create_auth_code(
        &self,
        auth_code_hash: &[u8],
        client_id: &str,
        redirect_uri: &str,
        code_challenge: &[u8],
        expires_at: i64,
        user_id: Uuid,
        device_name: Option<&str>,
    ) -> anyhow::Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO auth_codes (auth_code_hash, client_id, redirect_uri, code_challenge, expires_at, user_id, device_name)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
            auth_code_hash,
            client_id,
            redirect_uri,
            code_challenge,
            expires_at,
            user_id,
            device_name
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_auth_code_by_hash(
        &self,
        auth_code_hash: &[u8],
    ) -> anyhow::Result<Option<AuthCode>> {
        let row = sqlx::query_as!(
            AuthCode,
            r#"
            SELECT auth_code_hash, client_id, redirect_uri, code_challenge, expires_at, user_id as "user_id: Uuid", is_used, device_name
            FROM auth_codes
            WHERE auth_code_hash = ?
            "#,
            auth_code_hash
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    pub async fn create_device_code(
        &self,
        device_code_hash: &[u8],
        user_code_hash: &[u8],
        expires_at: i64,
        device_name_hint: Option<&str>,
        device_ip_hint: Option<&str>,
    ) -> anyhow::Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO device_codes (device_code_hash, user_code_hash, expires_at, device_name_hint, device_ip_hint)
            VALUES (?, ?, ?, ?, ?)
            "#,
            device_code_hash,
            user_code_hash,
            expires_at,
            device_name_hint,
            device_ip_hint
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn exists_user_code(&self, user_code_hash: &[u8]) -> anyhow::Result<bool> {
        let row = sqlx::query!(
            r#"
            SELECT 1 as "exists: bool" FROM device_codes
            WHERE user_code_hash = ?
            "#,
            user_code_hash
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.is_some())
    }

    pub async fn get_device_code_by_user_code(
        &self,
        user_code_hash: &[u8],
    ) -> anyhow::Result<Option<DeviceCode>> {
        let row = sqlx::query_as!(
            DeviceCode,
            r#"
            SELECT device_code_hash, user_code_hash, expires_at, user_id as "user_id: Uuid", is_used, device_name_hint, device_ip_hint
            FROM device_codes
            WHERE user_code_hash = ?
            "#,
            user_code_hash
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    pub async fn get_device_code_by_device_code(
        &self,
        device_code_hash: &[u8],
    ) -> anyhow::Result<Option<DeviceCode>> {
        let row = sqlx::query_as!(
            DeviceCode,
            r#"
            SELECT device_code_hash, user_code_hash, expires_at, user_id as "user_id: Uuid", is_used, device_name_hint, device_ip_hint
            FROM device_codes
            WHERE device_code_hash = ?
            "#,
            device_code_hash
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    pub async fn set_device_code_user_id(
        &self,
        device_code_hash: &[u8],
        user_id: Uuid,
    ) -> anyhow::Result<()> {
        sqlx::query!(
            r#"
            UPDATE device_codes
            SET user_id = ?
            WHERE device_code_hash = ?
            "#,
            user_id,
            device_code_hash
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn set_device_code_used(&self, device_code_hash: &[u8]) -> anyhow::Result<()> {
        sqlx::query!(
            r#"
            UPDATE device_codes
            SET is_used = 1
            WHERE device_code_hash = ?
            "#,
            device_code_hash
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn authenticate(&self, provider: &str, subject: &str) -> anyhow::Result<User> {
        let row = sqlx::query!(
            r#"
            SELECT user_id as "user_id: Uuid" FROM credentials
            WHERE provider = ? AND subject = ?
            "#,
            provider,
            subject
        )
        .fetch_optional(&self.pool)
        .await?;

        let user_id = if let Some(row) = row {
            row.user_id
        } else {
            let mut tx = self.pool.begin().await?;

            let user_id = Uuid::new_v4();
            sqlx::query!(
                r#"
                INSERT INTO users (id) VALUES (?)
                "#,
                user_id
            )
            .execute(&mut *tx)
            .await?;

            sqlx::query!(
                r#"
                INSERT INTO credentials (provider, subject, user_id)
                VALUES (?, ?, ?)
                "#,
                provider,
                subject,
                user_id
            )
            .execute(&mut *tx)
            .await?;

            tx.commit().await?;

            user_id
        };

        Ok(User { id: user_id })
    }

    pub async fn create_session(
        &self,
        id: Uuid,
        token_hash: &[u8],
        user_id: Uuid,
        device_name: Option<&str>,
    ) -> sqlx::Result<()> {
        let last_used_at = now();

        sqlx::query!(
            r#"
            INSERT INTO sessions (id, token_hash, last_used_at, user_id, device_name)
            VALUES (?, ?, ?, ?, ?)
            "#,
            id,
            token_hash,
            last_used_at,
            user_id,
            device_name
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_session_by_token_hash(
        &self,
        token_hash: &[u8],
    ) -> sqlx::Result<Option<Session>> {
        let row = sqlx::query_as!(
            Session,
            r#"
            SELECT id as "id: Uuid", token_hash, last_used_at, user_id as "user_id: Uuid", device_name
            FROM sessions
            WHERE token_hash = ?
            "#,
            token_hash
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    pub async fn update_session_last_used(&self, token_hash: &[u8]) -> sqlx::Result<()> {
        let last_used_at = now();

        sqlx::query!(
            r#"
            UPDATE sessions
            SET last_used_at = ?
            WHERE token_hash = ?
            "#,
            last_used_at,
            token_hash
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_sessions_by_user_id(&self, user_id: Uuid) -> sqlx::Result<Vec<Session>> {
        let rows = sqlx::query_as!(
            Session,
            r#"
            SELECT id as "id: Uuid", token_hash, last_used_at, user_id as "user_id: Uuid", device_name
            FROM sessions
            WHERE user_id = ?
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    pub async fn delete_session_by_session_id_and_user_id(
        &self,
        session_id: Uuid,
        user_id: Uuid,
    ) -> sqlx::Result<bool> {
        let res = sqlx::query!(
            r#"
            DELETE FROM sessions
            WHERE id = ? AND user_id = ?
            "#,
            session_id,
            user_id
        )
        .execute(&self.pool)
        .await?;

        Ok(res.rows_affected() > 0)
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[cfg(test)]
mod test {
    #[tokio::test]
    async fn authenticate_same_subjects() {
        let database = super::Database::open_memory().await.unwrap();

        let user1 = database
            .authenticate("test_provider", "test_subject")
            .await
            .unwrap();
        let user2 = database
            .authenticate("test_provider", "test_subject")
            .await
            .unwrap();

        assert_eq!(user1.id, user2.id);
    }

    #[tokio::test]
    async fn authenticate_different_subjects() {
        let database = super::Database::open_memory().await.unwrap();

        let user1 = database
            .authenticate("test_provider", "test_subject1")
            .await
            .unwrap();
        let user2 = database
            .authenticate("test_provider", "test_subject2")
            .await
            .unwrap();

        assert_ne!(user1.id, user2.id);
    }
}
