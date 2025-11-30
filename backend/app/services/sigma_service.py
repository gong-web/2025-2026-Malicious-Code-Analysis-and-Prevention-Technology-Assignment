from app.core.sigma_engine import SigmaEngine
import os

# Global singleton
_sigma_engine = None

def get_sigma_engine() -> SigmaEngine:
    global _sigma_engine
    if _sigma_engine is None:
        # Assuming the CWD is the backend root
        rules_dir = os.getenv("SIGMA_RULES_DIR", "../data/sigma_rules")
        # Correct path adjustment if needed. 
        # Since backend is in "backend/", and data is in "data/", 
        # if we run from "backend/", then "../data/sigma_rules" is correct.
        # Let's make it absolute to be safe
        
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        # backend/app/services -> backend/app -> backend -> root
        # actually backend/app/services is 3 levels deep from backend root if backend is root?
        # No. file is in backend/app/services/sigma_service.py
        # backend/ is the root of the python app usually?
        # The helper `main.py` is in `backend/`.
        # So `os.path.abspath(__file__)` = .../backend/app/services/sigma_service.py
        # dirname = .../backend/app/services
        # dirname = .../backend/app
        # dirname = .../backend
        # dirname = .../ (project root)
        
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        rules_dir = os.path.join(project_root, "data", "sigma_rules")
        
        print(f"Initializing Sigma Engine with rules from: {rules_dir}")
        _sigma_engine = SigmaEngine(rules_dir)
        
    return _sigma_engine
