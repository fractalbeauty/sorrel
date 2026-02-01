use sqlx::sqlite::SqlitePoolOptions;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Database {
    pool: sqlx::SqlitePool,
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
