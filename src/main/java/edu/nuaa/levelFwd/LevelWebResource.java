package edu.nuaa.levelFwd;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.onosproject.net.HostId;
import org.onosproject.rest.AbstractWebResource;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.util.Iterator;
import java.util.List;

/**
 * Sample web resource.
 */
@Path("level")
public class LevelWebResource extends AbstractWebResource {

    /**
     * Get hello world greeting.
     *
     * @return 200 OK
     */
    @GET
    @Path("test")
    public Response getGreeting() {
        ObjectNode node = mapper().createObjectNode().put("hello", "world");
        return ok(node).build();
    }

    @GET
    @Path("hosts")
    public Response getHostInfos() {
        List<HostInfo> infos = get(LevelService.class).getHostInfos();

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode root = mapper.createObjectNode();
        ArrayNode arrayNode = mapper.createArrayNode();

        for (HostInfo info : infos) {
            ObjectNode node = mapper.createObjectNode();

            node.put("hostId", info.id().toString());
            node.put("vlanId", info.vlanId().toString());
            node.put("deviceId", info.deviceId().toString());
            node.put("mac", info.srcMAC().toString());
            node.put("ip", info.rule().level().getIp().toString());
            node.put("levels", info.rule().toString());


            arrayNode.add(node);
        }

        root.set("hosts", arrayNode);

        return Response.ok(root.toString(), MediaType.APPLICATION_JSON_TYPE).build();
    }

    /**
     * Get HostInfo By HostId.
     *
     * @param id HostId except the suffix "/None"
     * @return HostInfo in JSON.
     */
    @GET
    @Path("host/{id}")
    public Response getHostInfoById(@PathParam("id") String id) throws URISyntaxException {
        HostInfo info = get(LevelService.class).getHostInfo(HostId.hostId(id + "/None"));
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode node = mapper.createObjectNode();
        node.put("hostId", info.id().toString());
        node.put("vlanId", info.vlanId().toString());
        node.put("deviceId", info.deviceId().toString());
        node.put("ip", info.Ip().toString());
        node.put("mac", info.srcMAC().toString());
        node.setAll(ruleToJson(info.rule()));
        return Response.ok(node.toString(), MediaType.APPLICATION_JSON_TYPE).build();
    }

    /**
     * Turns the LevelRule to Json Node.
     */
    private ObjectNode ruleToJson(LevelRule rule) {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode node = mapper.createObjectNode();
        node.put("level", rule.level().toString());
        ArrayNode arrayNode = mapper.createArrayNode();
        for (String s : rule.service()) {
            arrayNode.add(s);
        }
        node.set("service", arrayNode);
        return node;
    }

    /**
     * Set MiddleBox MAC Address
     */
    @POST
    @Path("middlebox")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response setMiddleBoxes(InputStream input) throws URISyntaxException {
        Level[] levels = get(LevelService.class).getLevelDef();

        JsonNode node;
        try {
            node = mapper().readTree(input);
        } catch (IOException e) {
            throw new IllegalArgumentException("Unable to parse level request", e);
        }

        Iterator<JsonNode> innerNodes = node.path("middleBox").elements();
        while (innerNodes.hasNext()) {
            JsonNode innerNode = innerNodes.next();

            for (Level level : levels) {
                if (level.getCode() == innerNode.path("code").asInt()) {
                    level.setIp(innerNode.path("MiddleBox ip").asText());
                    level.setMac(innerNode.path("MiddleBox mac").asText());
                }
            }
        }
        return Response.noContent().build();
    }

    /**
     * Get Middle Boxes.
     * Returns array of the middle boxes.
     *
     * @return 200 OK
     */
    @GET
    @Path("middlebox")
    public Response getMiddleBoxes() {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode root = mapper.createObjectNode();
        ArrayNode arrayNode = mapper.createArrayNode();
        for (Level level : get(LevelService.class).getLevelDef()) {
            ObjectNode node = mapper.createObjectNode();
            node.put("name", level.name());
            node.put("code", level.getCode());
            node.put("MiddleBox ip", level.getIp().toString());
            node.put("MiddleBox mac", level.getMac().toString());
            arrayNode.add(node);
        }
        root.set("middleBox", arrayNode);
        return Response.ok(root, MediaType.APPLICATION_JSON_TYPE).build();
    }

    /**
     * Clear Middle Boxes.
     * @return 204 NO CONTENT
     */
    @DELETE
    @Path("middlebox")
    public Response clearMiddleBoxes() {
        Level[] levels = get(LevelService.class).getLevelDef();
        for (Level level : levels) {
            level.setIp("0.0.0.0");
        }
        return Response.noContent().build();
    }
}
