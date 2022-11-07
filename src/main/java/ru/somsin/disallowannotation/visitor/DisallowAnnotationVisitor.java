package ru.somsin.disallowannotation.visitor;

import org.objectweb.asm.*;
import org.objectweb.asm.commons.Method;
import org.yaml.snakeyaml.Yaml;
import ru.somsin.disallowannotation.model.MethodData;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.annotation.Annotation;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;

/**
 * Visitor for disallow annotation
 */
public class DisallowAnnotationVisitor {
    private final String INIT = "<init>";
    private final String CL_INIT = "<clinit>";
    private final String DOT_CLASS = ".class";

    private final Class<? extends Annotation> forbiddenAnnotationClass;
    private final Class<? extends Annotation> markerAnnotationClass;

    private String targetClass;
    private Method targetMethod;

    private DisallowAnnotationClassVisitor classVisitor;

    private final List<Path> pathsToClasses = new ArrayList<>();
    private final Set<Node> roots = new HashSet<>();
    private final Map<java.lang.reflect.Method, Set<Node>> invokeDynamic = new HashMap<>();

    private boolean foundForbiddenAnnotation = false;

    /**
     * Init
     *
     * @param markerAnnotationClass    Annotation for marking the root method (example: @DisallowTransactional)
     * @param forbiddenAnnotationClass Forbidden annotation in the root method call chain (example: org.spring...@Transactional)
     */
    public DisallowAnnotationVisitor(Class<? extends Annotation> markerAnnotationClass, Class<? extends Annotation> forbiddenAnnotationClass) {
        this.markerAnnotationClass = markerAnnotationClass;
        this.forbiddenAnnotationClass = forbiddenAnnotationClass;
    }

    /**
     * Run a check
     *
     * @throws Exception In case of errors
     */
    public void run() throws Exception {
        try (InputStream input = DisallowAnnotationVisitor.class.getClassLoader().getResourceAsStream("application.yaml")) {
            Map<String, Map<String, Map<String, String>>> properties = new Yaml().load(input);
            String buildDir = properties.get("disallow-annotation").get("build").get("dir");

            Files.walkFileTree(Paths.get(buildDir), new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) {
                    String fileName = file.getFileName().toString();

                    if (fileName.endsWith(DOT_CLASS)) {
                        pathsToClasses.add(file);
                    }

                    return FileVisitResult.CONTINUE;
                }
            });
        }

        classVisitor = new DisallowAnnotationClassVisitor(true);
        acceptStream(pathsToClasses);
        classVisitor.determineRootNodes = false;

        for (Node root : roots) {
            determineNodes(root);
        }
    }

    /**
     * Roots get
     *
     * @return Set of nodes
     */
    public Set<Node> getRoots() {
        return roots;
    }

    /**
     * Forbidden annotation indication
     *
     * @return true if it has
     */
    public boolean isFoundForbiddenAnnotation() {
        return foundForbiddenAnnotation;
    }

    private static class Node {
        private final Class<?> clazz;
        private final MethodData methodData;
        private final Set<Node> nodes = new HashSet<>();

        public Node(Class<?> clazz, MethodData methodData) {
            this.clazz = clazz;
            this.methodData = methodData;
        }

        public Class<?> getClazz() {
            return clazz;
        }

        public MethodData getMethodData() {
            return methodData;
        }

        public Set<Node> getNodes() {
            return nodes;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Node node = (Node) o;
            return Objects.equals(clazz, node.clazz) && Objects.equals(methodData, node.methodData);
        }

        @Override
        public int hashCode() {
            return Objects.hash(clazz, methodData);
        }
    }

    private Class<?>[] determineParameters(String descriptor) {
        Type[] argumentTypes = Type.getArgumentTypes(descriptor);
        List<Class<?>> parameters = new ArrayList<>(argumentTypes.length);

        for (Type type : argumentTypes) {
            switch (type.getSort()) {
                case Type.ARRAY:
                    try {
                        parameters.add(Class.forName(type.getDescriptor().replace('/', '.')));
                    } catch (ClassNotFoundException e) {
                        throw new RuntimeException(e);
                    }
                    break;
                case Type.BOOLEAN:
                    parameters.add(boolean.class);
                    break;
                case Type.BYTE:
                    parameters.add(byte.class);
                    break;
                case Type.CHAR:
                    parameters.add(char.class);
                    break;
                case Type.SHORT:
                    parameters.add(short.class);
                    break;
                case Type.INT:
                    parameters.add(int.class);
                    break;
                case Type.FLOAT:
                    parameters.add(float.class);
                    break;
                case Type.DOUBLE:
                    parameters.add(double.class);
                    break;
                case Type.LONG:
                    parameters.add(long.class);
                    break;
                default:
                    try {
                        parameters.add(Class.forName(type.getClassName()));
                    } catch (ClassNotFoundException e) {
                        throw new RuntimeException(e);
                    }
                    break;
            }
        }

        return parameters.toArray(new Class[]{});
    }

    private class DisallowAnnotationClassVisitor extends ClassVisitor {
        private final DisallowAnnotationMethodVisitor methodVisitor = new DisallowAnnotationMethodVisitor();

        private Class<?> clazz;
        private java.lang.reflect.Method method;
        private Node node;

        private boolean determineRootNodes;

        public DisallowAnnotationClassVisitor(boolean determineRootNodes) {
            super(Opcodes.ASM9);
            this.determineRootNodes = determineRootNodes;
        }

        @Override
        public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
            try {
                clazz = Class.forName(Type.getObjectType(name).getClassName());
            } catch (ClassNotFoundException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            if (INIT.equals(name) || CL_INIT.equals(name)) {
                return null;
            }

            try {
                method = clazz.getDeclaredMethod(name, determineParameters(descriptor));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            if (!determineRootNodes) {
                return methodVisitor;
            }

            boolean hasForbiddenAnnotation = false;
            boolean hasMarkerAnnotation = false;

            for (Annotation annotation : method.getDeclaredAnnotations()) {
                Class<? extends Annotation> annotationType = annotation.annotationType();

                if (annotationType.equals(markerAnnotationClass)) {
                    hasMarkerAnnotation = true;
                } else if (annotationType.equals(forbiddenAnnotationClass)) {
                    hasForbiddenAnnotation = true;
                }
            }

            if (hasMarkerAnnotation) {
                MethodData methodData = new MethodData(method, hasForbiddenAnnotation);
                Node node = new Node(clazz, methodData);
                roots.add(node);
            }

            return methodVisitor;
        }

        private class DisallowAnnotationMethodVisitor extends MethodVisitor {
            public DisallowAnnotationMethodVisitor() {
                super(Opcodes.ASM9);
            }

            @Override
            public void visitInvokeDynamicInsn(String name, String descriptor, Handle bootstrapMethodHandle, Object... bootstrapMethodArguments) {
                if (!classVisitor.determineRootNodes) {
                    return;
                }

                for (Object bootstrapMethodArgument : bootstrapMethodArguments) {
                    if (bootstrapMethodArgument instanceof Handle) {
                        Handle handle = (Handle) bootstrapMethodArgument;
                        boolean hasTransactional = false;

                        for (Annotation annotation : method.getDeclaredAnnotations()) {
                            if (annotation.annotationType().equals(forbiddenAnnotationClass)) {
                                hasTransactional = true;
                                break;
                            }
                        }

                        MethodData methodData = new MethodData(method, hasTransactional);
                        Node node = new Node(clazz, methodData);

                        Class<?> invokeClass;
                        try {
                            invokeClass = Class.forName(Type.getObjectType(handle.getOwner()).getClassName());
                        } catch (ClassNotFoundException e) {
                            throw new RuntimeException(e);
                        }

                        java.lang.reflect.Method invokeMethod;
                        try {
                            invokeMethod = invokeClass.getDeclaredMethod(handle.getName(), determineParameters(handle.getDesc()));
                        } catch (NoSuchMethodException e) {
                            throw new RuntimeException(e);
                        }

                        Set<Node> nodes = invokeDynamic.get(invokeMethod);

                        if (nodes == null || nodes.size() == 0) {
                            nodes = new HashSet<>();
                            invokeDynamic.put(invokeMethod, nodes);
                        }

                        nodes.add(node);
                    }
                }

                super.visitInvokeDynamicInsn(name, descriptor, bootstrapMethodHandle, bootstrapMethodArguments);
            }

            @Override
            public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
                if (owner.equals(targetClass) && name.equals(targetMethod.getName()) && descriptor.equals(targetMethod.getDescriptor())) {
                    boolean hasTransactional = false;

                    for (Annotation annotation : method.getDeclaredAnnotations()) {
                        if (annotation.annotationType().equals(forbiddenAnnotationClass)) {
                            hasTransactional = true;
                        }
                    }

                    MethodData methodData = new MethodData(method, hasTransactional);
                    Node newNode = new Node(clazz, methodData);

                    node.getNodes().add(newNode);
                }
            }
        }
    }

    private void determineNodes(Node root) throws Exception {
        determineInnerNodes(root);

        for (Node node : root.getNodes()) {
            if (node.getMethodData().isHasForbiddenAnnotation()) {
                foundForbiddenAnnotation = true;
            }

            determineNodes(node);
        }
    }

    private void determineInnerNodes(Node node) throws Exception {
        targetClass = node.getClazz().getName().replace('.', '/');
        targetMethod = Method.getMethod(node.getMethodData().getMethod());
        classVisitor.node = node;

        acceptStream(pathsToClasses);

        java.lang.reflect.Method method = node.getMethodData().getMethod();
        Set<Node> nodes = invokeDynamic.get(method);

        if (nodes != null) {
            node.getNodes().addAll(nodes);
        }
    }

    private void acceptStream(List<Path> pathsToClasses) throws IOException {
        for (Path path : pathsToClasses) {
            try (InputStream stream = new BufferedInputStream(Files.newInputStream(path))) {
                new ClassReader(stream).accept(classVisitor, 0);
            }
        }
    }
}
