from datetime import datetime
from typing import Optional, List, Tuple, Dict, Any
from pydantic import BaseModel
from ..value_object.collect_result import CollectResult
from ..entity import Entity
from ..events import Events
from ..payload.event_payload import EventPayload
from ..profile import Profile
from ..session import Session
from ..metadata import Metadata
from ..time import Time
from ..value_object.bulk_insert_result import BulkInsertResult
from ..value_object.save_result import SaveResult
from ..value_object.tracker_payload_result import TrackerPayloadResult
from ...config import tracardi
from ...process_engine.rules_engine import RulesEngine


class TrackerPayload(BaseModel):
    source: Entity
    session: Entity

    metadata: Optional[Metadata]
    profile: Optional[Entity] = None
    context: Optional[dict] = {}
    properties: Optional[dict] = {}
    events: List[EventPayload] = []
    options: Optional[dict] = {}

    def __init__(self, **data: Any):
        data['metadata'] = Metadata(
            time=Time(
                insert=datetime.utcnow()
            ))
        super().__init__(**data)

    def get_events(self, session: Session, profile: Profile) -> Events:
        _events = Events()
        if self.events:
            for event in self.events:  # type: EventPayload
                if event.is_persistent():
                    _event = event.to_event(self.metadata, self.source, session, profile, self.options)
                    _events.append(_event)
        return _events

    def return_profile(self):
        return self.options and "profile" in self.options and self.options['profile'] is True

    async def collect(self, save_session=True, save_events=True, save_profile=True) -> Tuple[
        Profile, Session, Events, CollectResult]:

        # Get profile, session objects
        profile, session = await self._get_profile_and_session()

        # Presistence

        # Save profile
        if save_profile and profile.metadata.new:
            profile_result = await profile.storage().save()
        else:
            profile_result = BulkInsertResult()

        # Save session
        if save_session and (session.metadata.new or session.profile is None or session.profile.id != profile.id):
            # save only profile Entity
            session.profile = Entity(id=profile.id)
            session_result = await session.storage().save()
        else:
            session_result = BulkInsertResult()

        # Save events
        if save_events:
            events = self.get_events(session, profile)
            event_result = await events.bulk().save()
            event_result = SaveResult(**event_result.dict())

            # Add event types
            for event in events:
                event_result.types.append(event.type)
        else:
            events = Events()
            event_result = BulkInsertResult()

        result = {
            "session": session_result,
            "events": event_result,
            "profile": profile_result

        }
        return profile, session, events, CollectResult(**result)

    async def _get_profile_and_session(self) -> Tuple[Profile, Session]:

        """
        Returns session. Creates profile if it does not exist.If it exists connects session with profile.
        """

        if self.session.id is None:
            raise ValueError("Session must be set.")

        # Load session from storage
        if isinstance(self.session, Entity):
            session = await self.session.storage("session").load(Session)
        else:
            raise ValueError(
                "Session has unknown type. Available types Entity, Session. `{}` given".format(type(self.session)))

        is_new_profile = False
        is_new_session = False

        if session is None:

            session = Session(id=self.session.id)
            is_new_session = True

            # Bind profile

            if self.profile is None:

                # Create empty default profile generate profile_id
                profile = Profile.new()

                # Create new profile
                is_new_profile = True

            else:

                # Id exists load profile

                profile = await self.profile.storage("profile").load(Profile)  # type: Profile

                if profile is None:
                    # Id exists but profile not exist in storage.
                    # Id was forged

                    profile = Profile.new()

                    # Create new profile
                    is_new_profile = True

        else:

            # There is session. Copy profile id form session to profile

            if session.profile is not None:
                # Loaded session has profile

                profile = Profile(id=session.profile.id)
                profile = await profile.storage().load()  # type: Profile
            else:
                # Corrupted session

                profile = None

            if profile is None:
                # Id exists but profile not exist in storage.

                profile = Profile.new()

                # Create new profile
                is_new_profile = True

        # Fill with data
        # source = Source(id=self.source.id)
        # source.properties = self.event_server
        session.context = self.context
        session.properties = self.properties
        session.metadata.new = is_new_session

        profile.metadata.new = is_new_profile

        return profile, session

    async def process(self) -> Tuple[dict, Profile]:

        profile, session, events, collect_result = await self.collect()

        rules_engine = RulesEngine(
            session,
            profile,
            events)

        flow_result, segmentation_result = await rules_engine.execute(self.source.id)

        flow_response = []
        for event_type, debugging in flow_result.items():
            for debug_infos in debugging:
                for rule_id, debug_info in debug_infos.items():
                    flow_response.append([
                        debug_info.event.id,
                        event_type,
                        rule_id,
                        debug_info.flow.id,
                        debug_info.dict(include={"flow": {"error": ...}})
                    ]
                    )

        # Prepare response
        result = {}

        # Debugging
        #todo save result to different index
        if tracardi.track_debug:
            debug_result = TrackerPayloadResult(**collect_result.dict())
            debug_result = debug_result.dict()
            debug_result['execution'] = flow_response
            debug_result['segmentation'] = segmentation_result
            result['debugging'] = debug_result

        # Profile
        if self.return_profile():
            result["profile"] = profile.dict(exclude={"properties": {"private": ...}})
        else:
            result["profile"] = profile.dict(include={"id": ...})

        return result, profile
