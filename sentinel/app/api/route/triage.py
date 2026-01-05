from fastapi import APIRouter, HTTPException
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from app.prompts.triage import TRIAGE_PROMPT
from app.core.model import models
from app.logger import logger
import json
from app.schemas.triage import TriageResult

router = APIRouter(tags=["triage"])


parser = JsonOutputParser(pydantic_object=TriageResult)


@router.post("/triage/analyze")
async def alert_analyze(state:dict):
    try:
        # print(state,"payload")
        enrich_data_str = json.dumps(state, indent=2)

        PROMPT = PromptTemplate.from_template(
            template=TRIAGE_PROMPT,
            partial_variables={"format_instructions": parser.get_format_instructions()},
        )

        chain = PROMPT | models.GEMINI | parser

        response = await chain.ainvoke({"ENRICH_DATA": enrich_data_str})

        if not isinstance(response, dict):
            response = json.loads(response)

        triage = normalize_triage_output(
            response,
            indicator=state.get("indicator")
        )

        print(triage,"FROM LLM")

        return {"triage": triage}

    except Exception as error:
        logger.exception(f"Triage failed - {error}")
        raise HTTPException(500, "Triage analysis failed")

        
        



def normalize_triage_output(result: dict, indicator: str) -> dict:
    # Correct output
    if "triage" in result:
        return result["triage"]

    # Model keyed by indicator
    indicator_key = f"indicator_{indicator}"
    if indicator_key in result:
        return result[indicator_key]

    # Single-key fallback
    if len(result) == 1:
        return list(result.values())[0]

    raise ValueError("Invalid triage response format")
