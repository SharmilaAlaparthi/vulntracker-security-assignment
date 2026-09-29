from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from config import DATABASE_URL

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def search_scans_by_query(db, query: str, owner_id: int) -> list:
    """Full-text-ish search across scan columns, scoped to a single owner.

    Uses bound parameters (never string interpolation) so the query text can
    never alter the SQL structure — this closes the SQL-injection hole. The
    caller-supplied `query` is treated purely as data. Results are also
    restricted to `owner_id` so one user cannot search another user's scans.
    """
    # Escape LIKE wildcards in user input so `%` / `_` are matched literally.
    escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    like = f"%{escaped}%"
    sql = text(
        "SELECT id, title, description, severity, status, cve_id, "
        "affected_component, owner_id, created_at FROM scan_results "
        "WHERE owner_id = :owner_id AND ("
        "title LIKE :like ESCAPE '\\' "
        "OR description LIKE :like ESCAPE '\\' "
        "OR cve_id LIKE :like ESCAPE '\\')"
    )
    result = db.execute(sql, {"like": like, "owner_id": owner_id})
    return [dict(row._mapping) for row in result]