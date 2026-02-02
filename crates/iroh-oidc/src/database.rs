use sqlx::sqlite::SqlitePoolOptions;
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
}
